"""The governed runtime.

    agent proposes  →  grant check  →  policy  →  rate limit  →  human approval  →  execute  →  ledger
                         (task scope)   (rules)                  (bound to exact call)

`Runtime` holds the policy, tools, keys, ledger and approval queue.
`Session` is one task run: it enforces budgets, checkpoints after every
step, and can be suspended while a human decides and resumed later — a
completed calls replay, while uncertain outcomes require reconciliation.
"""

from __future__ import annotations

import json
import copy
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from .approvals import APPROVED, PENDING, Approval, ApprovalStore
from .grants import Grant
from .authority import Authority
from .storage import load_signed, locked, private_dir, save_signed
from .ledger import Ledger
from .policy import ALLOW, APPROVE, DENY, THROTTLE, Decision, Policy
from .util import canonical, digest, load_or_create_key, now, redact, short

OK, DENIED, ERROR, PENDING_STATUS = "ok", "denied", "error", "pending"


class BudgetExceeded(RuntimeError):
    pass


class RunSuspended(RuntimeError):
    def __init__(self, approval_id: str) -> None:
        super().__init__(f"run suspended awaiting human approval {approval_id}")
        self.approval_id = approval_id


@dataclass
class ToolSpec:
    name: str
    fn: Callable[..., Any]
    side_effect: bool = False
    description: str = ""


@dataclass
class ToolResult:
    call_id: str
    tool: str
    status: str
    output: Any = None
    decision: dict[str, Any] = field(default_factory=dict)
    approval_id: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == OK

    def message(self) -> str:
        """What the agent/model is told. Denials are explicit so the model can re-plan."""
        if self.status == OK:
            return self.output if isinstance(self.output, str) else canonical(self.output)
        if self.status == DENIED:
            return f"[jackline] DENIED {self.tool}: {'; '.join(self.decision.get('reasons', []))}"
        if self.status == PENDING_STATUS:
            return f"[jackline] {self.tool} is awaiting human approval ({self.approval_id})"
        return f"[jackline] ERROR {self.tool}: {self.output}"

    def to_dict(self) -> dict[str, Any]:
        return {"call_id": self.call_id, "tool": self.tool, "status": self.status,
                "output": self.output, "decision": self.decision, "approval_id": self.approval_id}


Approver = Callable[[Approval], "tuple[bool, str, str]"]  # → (approve?, approver identity, reason)


class Runtime:
    def __init__(self, policy: Policy, home: str | Path = ".jackline", key: bytes | None = None,
                 require_grant: bool = True, approval_mode: str = "suspend",
                 approver: Approver | None = None, fsync: bool = True,
                 trusted_local_approvals: bool = False) -> None:
        if approval_mode not in ("suspend", "wait", "callback"):
            raise ValueError("approval_mode must be suspend | wait | callback")
        if approval_mode == "callback" and approver is None:
            raise ValueError("approval_mode='callback' needs an approver function")
        self.policy = policy
        self.home = Path(home)
        private_dir(self.home)
        self.key = key or load_or_create_key(self.home / "jackline.key")
        self.ledger = Ledger(self.home / "ledger.jsonl", self.key, fsync=fsync)
        self.approvals = ApprovalStore(self.home / "approvals", self.key, policy.approver_keys, trusted_local_approvals)
        self.require_grant = require_grant
        self.approval_mode = approval_mode
        self.approver = approver
        self.authority = Authority(self.home, self.key)
        self.tools: dict[str, ToolSpec] = {}

    # ------------------------------------------------------------------ tools
    def tool(self, name: str, side_effect: bool = False, description: str = ""):
        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.register(name, fn, side_effect, description or (fn.__doc__ or "").strip())
            return fn
        return deco

    def register(self, name: str, fn: Callable[..., Any], side_effect: bool = False, description: str = "") -> None:
        self.tools[name] = ToolSpec(name, fn, side_effect, description)

    def visible_tools(self) -> list[ToolSpec]:
        """Tools the model is allowed to know about. If no rule can ever run it, the model never sees it."""
        return [t for t in self.tools.values() if self.policy.can_ever_run(t.name)]

    # ------------------------------------------------------------------- gate
    def gate(self, tool: str, args: dict[str, Any], grant: Grant | None, grant_calls: int) -> Decision:
        """Decision preview only. Session.call enforces task binding, durable counters and rates."""
        if self.require_grant:
            if grant is None:
                return Decision(DENY, ["no-grant"], ["no task grant — standing authority is not allowed"],
                                self.policy.source_digest)
            why = grant.check(self.key, tool, grant_calls)
            if why:
                return Decision(DENY, ["grant"], [why], self.policy.source_digest)
        d = self.policy.evaluate(tool, args)
        return d

    # --------------------------------------------------------------- sessions
    def session(self, task: str, grant: Grant | None = None, run_id: str | None = None,
                *, task_id: str | None = None) -> "Session":
        return Session(self, task, grant, run_id, task_id=task_id)

    def resume(self, run_id: str, grant: Grant | None = None) -> "Session":
        state = Session.load_state(self.home, run_id, self.key)
        return Session(self, state["task"], grant, run_id, state=state, task_id=state["task_id"])

    def run_agent(self, agent: "Agent", task: str, grant: Grant | None = None, *,
                  task_id: str | None = None, model_limits: dict | None = None) -> "Session":
        """Drive an agent that *proposes* actions; the runtime decides what actually happens."""
        budget = self.policy.budget
        if model_limits is None and any(cap is not None for cap in
                (budget.max_model_calls, budget.max_tokens, budget.max_cost_usd)):
            raise ValueError("run_agent requires model_limits for preflight model budgets")
        s = self.session(task, grant, task_id=task_id)
        observations: list[dict[str, Any]] = []
        try:
            while True:
                s.step()
                action = (s.call_model(lambda: agent.next_action(task, observations), **model_limits)
                          if model_limits else agent.next_action(task, observations))
                if action and "usage" in action and not model_limits:
                    s.record_model(**action["usage"])
                if action is None or "final" in action:
                    s.finish("completed", (action or {}).get("final"))
                    return s
                if "tool" in action:
                    res = s.call(action["tool"], action.get("args", {}), action.get("id"))
                    observations.append(res.to_dict())
        except BudgetExceeded:
            return s
        except RunSuspended:
            return s


class Agent(Protocol):
    def next_action(self, task: str, observations: list[dict[str, Any]]) -> dict[str, Any] | None: ...


class Session:
    def __init__(self, rt: Runtime, task: str, grant: Grant | None, run_id: str | None = None,
                 state: dict[str, Any] | None = None, task_id: str | None = None) -> None:
        self.rt = rt
        self.grant = grant
        self.task = task
        self.task_id = task_id or task
        self.run_id = run_id or uuid.uuid4().hex[:12]
        if state is not None:
            self.state = state
            if (grant.grant_id if grant else None) != state.get("grant_id"):
                raise ValueError("resume requires the original grant")
            rt.ledger.append(self.run_id, "run.resumed", {"status": state["status"]})
            if state["status"] == "suspended":
                self.state["status"] = "running"
        else:
            self.state = {
                "run_id": self.run_id, "task": task, "task_id": self.task_id, "status": "running", "started_at": now(),
                "grant_id": grant.grant_id if grant else None, "steps": 0, "tool_calls": 0,
                "grant_calls": 0, "model_calls": 0, "tokens": 0, "cost_usd": 0.0, "executed": {},
                "pending": {}, "seq": 0, "events": {},
            }
            rt.ledger.append(self.run_id, "run.start", {
                "task": task, "policy": rt.policy.name, "policy_digest": rt.policy.source_digest[:16],
                "grant": {"id": grant.grant_id, "scopes": grant.scopes, "issued_by": grant.issued_by,
                          "expires_at": grant.expires_at} if grant else None,
                "require_grant": rt.require_grant,
            })
        with locked(self._state_path(rt.home, self.run_id).with_suffix(".lock")):
            if state is None and self._state_path(rt.home, self.run_id).exists():
                raise ValueError("run id already exists; use resume")
            if state is None:
                self._checkpoint()

    # ------------------------------------------------------------ persistence
    @staticmethod
    def _state_path(home: Path, run_id: str) -> Path:
        if not run_id.isalnum():
            raise ValueError("bad run id")
        return home / "runs" / f"{run_id}.json"

    @classmethod
    def load_state(cls, home: Path, run_id: str, key: bytes) -> dict[str, Any]:
        state = load_signed(cls._state_path(home, run_id), key)
        if state.get("run_id") != run_id:
            raise ValueError("checkpoint run id mismatch")
        return state

    def _checkpoint(self) -> None:
        state = copy.deepcopy(self.state)
        for entry in state["executed"].values():
            if "output" in entry:
                entry["output"] = redact(entry["output"])
        state["task"] = redact(state["task"])
        save_signed(self._state_path(self.rt.home, self.run_id), state, self.rt.key)

    def _reload(self) -> None:
        self.state = self.load_state(self.rt.home, self.run_id, self.rt.key)
        if self.state["status"] == "suspended":
            self.state["status"] = "running"

    # ----------------------------------------------------------------- budget
    @property
    def status(self) -> str:
        return self.state["status"]

    def _halt(self, limit: str, value: Any, cap: Any) -> None:
        self.state["status"] = "halted"
        self.rt.ledger.append(self.run_id, "budget.halt", {"limit": limit, "value": value, "cap": cap})
        self._checkpoint()
        raise BudgetExceeded(f"budget exceeded: {limit} = {value} (cap {cap})")

    def _ensure_running(self) -> None:
        if self.state["status"] == "halted":
            raise BudgetExceeded("run already halted by budget")
        if self.state["status"] not in ("running",):
            raise RuntimeError(f"run is {self.state['status']}")
        b = self.rt.policy.budget
        if b.max_wall_time_s is not None and now() - self.state["started_at"] > b.max_wall_time_s:
            self._halt("max_wall_time_s", round(now() - self.state["started_at"], 1), b.max_wall_time_s)

    def step(self) -> None:
        with locked(self._state_path(self.rt.home, self.run_id).with_suffix(".lock")):
            self._reload()
            self._step()
            self._checkpoint()

    def _step(self) -> None:
        self._ensure_running()
        self.state["steps"] += 1
        cap = self.rt.policy.budget.max_steps
        if cap is not None and self.state["steps"] > cap:
            self._halt("max_steps", self.state["steps"], cap)

    def record_model(self, model: str, input_tokens: int = 0, output_tokens: int = 0) -> None:
        """Post-response accounting only; use call_model for preflight budget enforcement."""
        with locked(self._state_path(self.rt.home, self.run_id).with_suffix(".lock")):
            self._reload()
            self._record_model(model, input_tokens, output_tokens)

    def call_model(self, invoke: Callable[[], Any], *, model: str,
                   input_tokens_bound: int, output_tokens_bound: int) -> Any:
        """Reserve the full declared upper bound durably BEFORE invoking a provider.

        No refunds: failed/uncertain requests also consume their reservation. The
        adapter must enforce provider output limits and bound the complete input.
        """
        with locked(self._state_path(self.rt.home, self.run_id).with_suffix(".lock")):
            self._reload()
            self._record_model(model, input_tokens_bound, output_tokens_bound, reserved=True)
            return invoke()

    def _record_model(self, model: str, input_tokens: int, output_tokens: int, reserved: bool = False) -> None:
        self._ensure_running()
        if any(type(n) is not int or n < 0 for n in (input_tokens, output_tokens)):
            raise ValueError("token usage must be non-negative integers")
        if self.rt.policy.budget.max_cost_usd is not None and model not in self.rt.policy.budget.prices:
            raise ValueError(f"no configured price for {model!r}; model call refused")
        b = self.rt.policy.budget
        self.state["model_calls"] += 1
        self.state["tokens"] += int(input_tokens) + int(output_tokens)
        price = b.prices.get(model, {})
        cost = (input_tokens * price.get("input_per_mtok", 0) + output_tokens * price.get("output_per_mtok", 0)) / 1e6
        self.state["cost_usd"] = self.state["cost_usd"] + cost
        self.rt.ledger.append(self.run_id, "model.reserved" if reserved else "model.call", {
            "model": model, "input_tokens": input_tokens, "output_tokens": output_tokens,
            "cost_usd": round(cost, 6), "total_cost_usd": self.state["cost_usd"]})
        for name, val, cap in (("max_model_calls", self.state["model_calls"], b.max_model_calls),
                               ("max_tokens", self.state["tokens"], b.max_tokens),
                               ("max_cost_usd", self.state["cost_usd"], b.max_cost_usd)):
            if cap is not None and val > cap:
                self._halt(name, val, cap)
        self._checkpoint()

    # ------------------------------------------------------------------ calls
    def call(self, tool: str, args: dict[str, Any] | None = None, call_id: str | None = None) -> ToolResult:
        with locked(self._state_path(self.rt.home, self.run_id).with_suffix(".lock")):
            self._reload()
            return self._call(tool, args, call_id)

    def _call(self, tool: str, args: dict[str, Any] | None, call_id: str | None) -> ToolResult:
        if not isinstance(tool, str) or not tool:
            raise ValueError("tool must be a non-empty string")
        if args is not None and (not isinstance(args, dict) or any(not isinstance(k, str) for k in args)):
            raise ValueError("tool arguments must be a JSON object")
        args = json.loads(json.dumps(args if args is not None else {}, allow_nan=False))
        if call_id is None:
            self.state["seq"] += 1
            call_id = f"c{self.state['seq']}"
        call_id = str(call_id)
        call_digest = digest({"tool": tool, "args": args})

        # Completed calls replay; uncertain calls are never blindly retried.
        done = self.state["executed"].get(call_id)
        if done is not None:
            if done["digest"] != call_digest:
                d = Decision(DENY, ["replay-mismatch"], ["call id reused with different arguments"],
                             self.rt.policy.source_digest)
                self.rt.ledger.append(self.run_id, "decision", {"call_id": call_id, "tool": tool, **d.to_dict()})
                return ToolResult(call_id, tool, DENIED, None, d.to_dict())
            self.rt.ledger.append(self.run_id, "tool.replayed", {"call_id": call_id, "tool": tool})
            return ToolResult(call_id, tool, done["status"], done.get("output"), done.get("decision", {}),
                              done.get("approval_id"))

        self._ensure_running()
        pending_aid = self.state["pending"].get(call_id)
        if not pending_aid:
            self.state["tool_calls"] += 1
            cap = self.rt.policy.budget.max_tool_calls
            if cap is not None and self.state["tool_calls"] > cap:
                self._halt("max_tool_calls", self.state["tool_calls"], cap)
            self.rt.ledger.append(self.run_id, "tool.proposed", {"call_id": call_id, "tool": tool, "args": args,
                                                                 "digest": call_digest[:16]})
            self._checkpoint()
        decision = self._authorize(tool, args, call_id, call_digest)
        self.rt.ledger.append(self.run_id, "decision", {"call_id": call_id, "tool": tool, **decision.to_dict()})
        if pending_aid:
            pending = self.rt.approvals.get(pending_aid)
            if pending.policy_digest != self.rt.policy.source_digest or pending.call_digest != call_digest:
                decision = Decision(DENY, ["approval-stale"], ["approval policy or arguments changed"], self.rt.policy.source_digest)

        if decision.effect in (DENY, THROTTLE):
            return self._record_denied(call_id, tool, call_digest, decision)

        approval: Approval | None = None
        if decision.effect == APPROVE or pending_aid:
            approval = self._await_approval(call_id, tool, args, call_digest, decision, pending_aid)
            if approval.status == PENDING:
                return ToolResult(call_id, tool, PENDING_STATUS, None, decision.to_dict(), approval.id)
            if approval.status != APPROVED or approval.call_digest != call_digest:
                why = (f"human {approval.status} by {approval.resolved_by or 'nobody'}"
                       + (f": {approval.reason}" if approval.reason else ""))
                return self._record_denied(call_id, tool, call_digest,
                                           Decision(DENY, decision.rules, [why], decision.policy_digest), approval.id)

        # Waiting for a person may outlive the grant, run budget or approval itself.
        self._ensure_running()
        fresh = self._authorize(tool, args, call_id, call_digest)
        if fresh.effect == DENY or fresh.policy_digest != decision.policy_digest:
            return self._record_denied(call_id, tool, call_digest,
                Decision(DENY, fresh.rules, fresh.reasons + ["authorization changed before execution"], fresh.policy_digest))
        if approval and (approval.expires_at <= now() or approval.policy_digest != fresh.policy_digest):
            return self._record_denied(call_id, tool, call_digest,
                Decision(DENY, ["approval-expired"], ["approval no longer valid"], fresh.policy_digest))
        limited = self.rt.authority.rate(self.rt.policy, tool, args)
        if limited:
            self.rt.ledger.append(self.run_id, "decision", {"call_id": call_id, "tool": tool, **limited.to_dict()})
            return self._record_denied(call_id, tool, call_digest, limited)
        return self._execute(call_id, tool, args, call_digest, decision, approval.id if approval else None)

    def _authorize(self, tool, args, call_id, call_digest) -> Decision:
        if self.rt.require_grant or self.grant is not None:
            if self.grant is None:
                return Decision(DENY, ["no-grant"], ["no task grant"], self.rt.policy.source_digest)
            why = self.rt.authority.grant(self.grant, self.task_id, tool, self.run_id, call_id, call_digest)
            if why:
                return Decision(DENY, ["grant"], [why], self.rt.policy.source_digest)
        return self.rt.policy.evaluate(tool, args)

    def _await_approval(self, call_id: str, tool: str, args: dict[str, Any], call_digest: str,
                        decision: Decision, pending_aid: str | None) -> Approval:
        store = self.rt.approvals
        if pending_aid:
            a = store.get(pending_aid)
            assert a is not None
        else:
            a = store.request(self.run_id, call_id, tool, redact(args), call_digest, decision.reasons,
                              decision.approvers, self.rt.policy.approval_timeout_s, decision.policy_digest)
            self.rt.ledger.append(self.run_id, "approval.requested", {
                "call_id": call_id, "approval_id": a.id, "tool": tool, "approvers": a.approvers,
                "expires_in_s": round(a.expires_at - a.requested_at)})
        if a.status == PENDING:
            if self.rt.approval_mode == "callback":
                ok, by, reason = self.rt.approver(a)  # type: ignore[misc]
                a = store.resolve(a.id, ok, by, reason)
            elif self.rt.approval_mode == "wait":
                a = store.wait(a.id)
            else:
                self.state["pending"][call_id] = a.id
                self.state["status"] = "suspended"
                self._checkpoint()
                raise RunSuspended(a.id)
        self.state["pending"].pop(call_id, None)
        self.rt.ledger.append(self.run_id, "approval.resolved", {
            "call_id": call_id, "approval_id": a.id, "status": a.status, "by": a.resolved_by, "reason": a.reason})
        return a

    def _record_denied(self, call_id: str, tool: str, call_digest: str, decision: Decision,
                       approval_id: str | None = None) -> ToolResult:
        self.state["executed"][call_id] = {"digest": call_digest, "status": DENIED, "decision": decision.to_dict(),
                                           "approval_id": approval_id}
        self._checkpoint()
        return ToolResult(call_id, tool, DENIED, None, decision.to_dict(), approval_id)

    def _execute(self, call_id: str, tool: str, args: dict[str, Any], call_digest: str, decision: Decision,
                 approval_id: str | None) -> ToolResult:
        # Commit intent first. A crash after this point has an unknown outcome;
        # recovery returns this marker instead of invoking the tool a second time.
        self.state["executed"][call_id] = {"digest": call_digest, "status": "uncertain",
            "output": "Outcome uncertain; reconcile with the destination before starting a new call.",
            "decision": decision.to_dict(), "approval_id": approval_id}
        self._checkpoint()
        self.rt.ledger.append(self.run_id, "tool.intent", {"call_id": call_id, "tool": tool, "digest": call_digest})
        spec = self.rt.tools.get(tool)
        if spec is None:
            status, output = ERROR, f"tool {tool!r} is not registered with this runtime"
        else:
            try:
                status, output = OK, spec.fn(**args)
            except Exception as exc:  # tool failures are data, not crashes
                status, output = ERROR, f"{type(exc).__name__}: {exc}"
        try:
            json.dumps(output, allow_nan=False)
        except (TypeError, ValueError):
            output = f"[non-JSON tool output: {type(output).__name__}]"
        self.rt.ledger.append(self.run_id, "tool.result", {
            "call_id": call_id, "tool": tool, "status": status, "output_digest": digest(output)[:16],
            "preview": short(redact(output), 120)})
        self.state["executed"][call_id] = {"digest": call_digest, "status": status, "output": output,
                                           "decision": decision.to_dict(), "approval_id": approval_id}
        self._checkpoint()
        return ToolResult(call_id, tool, status, output, decision.to_dict(), approval_id)

    def finish(self, status: str = "completed", summary: Any = None) -> None:
        with locked(self._state_path(self.rt.home, self.run_id).with_suffix(".lock")):
            self._reload()
            self._finish(status, summary)

    def _finish(self, status: str, summary: Any) -> None:
        self.state["status"] = status
        self.rt.ledger.append(self.run_id, "run.end", {
            "status": status, "summary": short(summary, 200) if summary else None,
            **{k: self.state[k] for k in ("steps", "tool_calls", "model_calls", "tokens", "cost_usd")}})
        self._checkpoint()
