"""Deterministic policy engine.

A policy is a TOML file of rules. Each rule names the tools it covers (glob
patterns), an effect (allow / deny / approve) and optional conditions on the
call's arguments. Evaluation is pure: same policy + same call → same decision.

Precedence is fixed and fail-closed:
    any matching DENY   → deny
    any matching APPROVE → require human approval
    any matching ALLOW   → allow (subject to rate limits)
    nothing matches      → the policy default (deny unless you say otherwise)

Unknown keys are an error, not a warning: a typo in a deny rule must never
silently turn it off.
"""

from __future__ import annotations

import fnmatch
import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .util import digest, load_toml, parse_duration

ALLOW, DENY, APPROVE, THROTTLE = "allow", "deny", "approve", "throttle"
EFFECTS = (ALLOW, DENY, APPROVE)

CONDITION_KEYS = {
    "path_within", "path_not_within", "path_matches", "host_in", "host_not_in",
    "arg_matches", "arg_gt", "arg_lt", "args_contain",
}
RULE_KEYS = {"id", "tools", "effect", "when", "rate", "reason", "path_arg", "url_arg", "approvers", "description"}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    tools: tuple[str, ...]
    effect: str
    when: dict[str, Any] = field(default_factory=dict)
    rate: str | None = None
    reason: str = ""
    path_arg: str = "path"
    url_arg: str = "url"
    approvers: tuple[str, ...] = ()

    def covers(self, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(tool, pat) for pat in self.tools)


@dataclass
class Decision:
    effect: str
    rules: list[str]
    reasons: list[str]
    policy_digest: str
    approvers: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.effect == ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {"effect": self.effect, "rules": self.rules, "reasons": self.reasons,
                "policy": self.policy_digest[:16], "approvers": self.approvers}


@dataclass
class Budget:
    max_steps: int | None = None
    max_tool_calls: int | None = None
    max_model_calls: int | None = None
    max_tokens: int | None = None
    max_cost_usd: float | None = None
    max_wall_time_s: float | None = None
    prices: dict[str, dict[str, float]] = field(default_factory=dict)  # model → {input_per_mtok, output_per_mtok}


@dataclass
class Policy:
    name: str
    rules: list[Rule]
    default: str = DENY
    workspace: Path = field(default_factory=Path.cwd)
    approval_timeout_s: float = 300.0
    budget: Budget = field(default_factory=Budget)
    source_digest: str = ""

    # ----------------------------------------------------------------- loading
    @classmethod
    def from_toml(cls, text: str, base_dir: Path | None = None) -> "Policy":
        data = load_toml(text)
        return cls.from_dict(data, base_dir=base_dir, source_digest=digest(data))

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        p = Path(path)
        return cls.from_toml(p.read_text(), base_dir=p.resolve().parent)

    @classmethod
    def from_dict(cls, data: dict[str, Any], base_dir: Path | None = None, source_digest: str = "") -> "Policy":
        base_dir = base_dir or Path.cwd()
        unknown_top = set(data) - {"jackline", "rule", "budget", "approvals"}
        if unknown_top:
            raise PolicyError(f"unknown top-level section(s): {sorted(unknown_top)}")
        meta = data.get("jackline", {})
        default = meta.get("default", DENY)
        if default not in (ALLOW, DENY, APPROVE):
            raise PolicyError(f"jackline.default must be allow|deny|approve, got {default!r}")
        ws = Path(_resolve(meta.get("workspace", "."), base_dir))

        rules: list[Rule] = []
        seen: set[str] = set()
        for i, r in enumerate(data.get("rule", [])):
            unknown = set(r) - RULE_KEYS
            if unknown:
                raise PolicyError(f"rule #{i + 1} ({r.get('id', '?')}): unknown key(s) {sorted(unknown)}")
            rid = r.get("id") or f"rule-{i + 1}"
            if rid in seen:
                raise PolicyError(f"duplicate rule id {rid!r}")
            seen.add(rid)
            effect = r.get("effect")
            if effect not in EFFECTS:
                raise PolicyError(f"rule {rid!r}: effect must be one of {EFFECTS}, got {effect!r}")
            tools = r.get("tools")
            if isinstance(tools, str):
                tools = [tools]
            if not tools or not all(isinstance(t, str) for t in tools):
                raise PolicyError(f"rule {rid!r}: 'tools' must be a non-empty list of glob patterns")
            when = dict(r.get("when", {}))
            bad = set(when) - CONDITION_KEYS
            if bad:
                raise PolicyError(f"rule {rid!r}: unknown condition(s) {sorted(bad)}; allowed: {sorted(CONDITION_KEYS)}")
            for k in ("path_within", "path_not_within"):
                if k in when:
                    when[k] = [_resolve(p, ws) for p in when[k]]
            for k in ("arg_matches",):
                if k in when:
                    when[k] = {a: re.compile(p) for a, p in when[k].items()}
            if "args_contain" in when:
                when["args_contain"] = [re.compile(p) for p in when["args_contain"]]
            if r.get("rate"):
                _parse_rate(r["rate"])  # validate early
            rules.append(Rule(
                id=rid, tools=tuple(tools), effect=effect, when=when, rate=r.get("rate"),
                reason=r.get("reason", ""), path_arg=r.get("path_arg", "path"), url_arg=r.get("url_arg", "url"),
                approvers=tuple(r.get("approvers", ())),
            ))

        b = data.get("budget", {})
        unknown_b = set(b) - {"max_steps", "max_tool_calls", "max_model_calls", "max_tokens", "max_cost_usd",
                              "max_wall_time", "prices"}
        if unknown_b:
            raise PolicyError(f"unknown budget key(s): {sorted(unknown_b)}")
        budget = Budget(
            max_steps=b.get("max_steps"), max_tool_calls=b.get("max_tool_calls"),
            max_model_calls=b.get("max_model_calls"), max_tokens=b.get("max_tokens"),
            max_cost_usd=b.get("max_cost_usd"),
            max_wall_time_s=parse_duration(b["max_wall_time"]) if "max_wall_time" in b else None,
            prices=b.get("prices", {}),
        )
        appr = data.get("approvals", {})
        return cls(
            name=meta.get("name", "unnamed-policy"), rules=rules, default=default, workspace=ws,
            approval_timeout_s=parse_duration(appr.get("timeout", "5m")), budget=budget,
            source_digest=source_digest or digest(data),
        )

    # --------------------------------------------------------------- evaluate
    def evaluate(self, tool: str, args: dict[str, Any]) -> Decision:
        matched = [r for r in self.rules if r.covers(tool) and _conditions_hold(r, args, self.workspace)]
        for effect in (DENY, APPROVE, ALLOW):
            hits = [r for r in matched if r.effect == effect]
            if hits:
                approvers = sorted({a for r in hits for a in r.approvers})
                return Decision(effect, [r.id for r in hits],
                                [r.reason or f"{r.effect} by rule {r.id}" for r in hits],
                                self.source_digest, approvers)
        return Decision(self.default, [], [f"no rule matched — policy default is {self.default}"], self.source_digest)

    def can_ever_run(self, tool: str) -> bool:
        """False when no allow/approve rule could ever cover this tool (used to hide tools from the model)."""
        if self.default in (ALLOW, APPROVE):
            return True
        return any(r.covers(tool) and r.effect in (ALLOW, APPROVE) for r in self.rules)


# ------------------------------------------------------------------ helpers
def _resolve(p: str, workspace: Path) -> str:
    p = os.path.expanduser(str(p))
    return os.path.realpath(p if os.path.isabs(p) else os.path.join(workspace, p))


def _within(path: str, roots: list[str]) -> bool:
    return any(path == r or path.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _host_match(host: str, domains: list[str]) -> bool:
    return any(host == d.lower() or host.endswith("." + d.lower()) for d in domains)


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _conditions_hold(rule: Rule, args: dict[str, Any], workspace: Path) -> bool:
    w = rule.when
    if not w:
        return True
    raw_path = args.get(rule.path_arg)
    path = _resolve(raw_path, workspace) if isinstance(raw_path, str) and raw_path else None
    url = args.get(rule.url_arg)
    host = _host(url) if isinstance(url, str) else None

    # A path/url condition on a call that has no such argument does not match.
    if "path_within" in w and not (path and _within(path, w["path_within"])):
        return False
    if "path_not_within" in w and not (path and not _within(path, w["path_not_within"])):
        return False
    if "path_matches" in w and not (path and any(
            fnmatch.fnmatch(path, g) or fnmatch.fnmatch(os.path.basename(path), g) for g in w["path_matches"])):
        return False
    if "host_in" in w and not (host and _host_match(host, w["host_in"])):
        return False
    if "host_not_in" in w and not (host is not None and not _host_match(host, w["host_not_in"])):
        return False
    for arg, rx in w.get("arg_matches", {}).items():
        if not (isinstance(args.get(arg), (str, int, float)) and rx.search(str(args.get(arg)))):
            return False
    for arg, limit in w.get("arg_gt", {}).items():
        n = _num(args.get(arg))
        if n is None or not n > float(limit):
            return False
    for arg, limit in w.get("arg_lt", {}).items():
        n = _num(args.get(arg))
        if n is None or not n < float(limit):
            return False
    if "args_contain" in w:
        blob = " ".join(str(v) for v in _flatten(args))
        if not any(rx.search(blob) for rx in w["args_contain"]):
            return False
    return True


def _flatten(obj: Any):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _flatten(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _flatten(v)
    else:
        yield obj


_RATE = re.compile(r"^\s*(\d+)\s*/\s*(s|sec|second|m|min|minute|h|hour|d|day)\s*$")


def _parse_rate(rate: str) -> tuple[int, float]:
    m = _RATE.match(rate)
    if not m:
        raise PolicyError(f"bad rate {rate!r}; use e.g. '10/min'")
    unit = m.group(2)[0]
    return int(m.group(1)), {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


class RateLimiter:
    """Sliding-window limiter keyed by rule id. Deterministic given a clock."""

    def __init__(self, clock=time.monotonic) -> None:
        self.clock = clock
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, rule: Rule) -> bool:
        if not rule.rate:
            return True
        limit, window = _parse_rate(rule.rate)
        now = self.clock()
        q = self.hits[rule.id]
        while q and now - q[0] >= window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True
