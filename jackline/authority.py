"""Durable grant accounting and atomic rate limits shared by one runtime home."""
from __future__ import annotations

from .policy import ALLOW, APPROVE, THROTTLE, Decision, _conditions_hold, _parse_rate
from .storage import load_signed, locked, save_signed
from .util import now


class Authority:
    def __init__(self, home, key):
        self.path, self.key = home / "authority.json", key

    def grant(self, grant, task_id, tool, run_id, call_id, call_digest):
        with locked(self.path.with_suffix(".lock")):
            state = load_signed(self.path, self.key) if self.path.exists() else {"grants": {}, "rates": {}}
            uses = state["grants"].setdefault(grant.grant_id, {})
            request = f"{run_id}:{call_id}"
            why = grant.check(self.key, tool, 0 if request in uses else len(uses))
            if why:
                return why
            if grant.task_id != task_id:
                return "grant belongs to a different task"
            if request in uses and uses[request] != call_digest:
                return "grant reservation arguments changed"
            uses[request] = call_digest
            save_signed(self.path, state, self.key)
        return None

    def rate(self, policy, tool, args):
        # Apply all matching allow/approve limits, even when approval takes precedence.
        rules = [r for r in policy.rules if r.rate and r.effect in (ALLOW, APPROVE)
                 and r.covers(tool) and _conditions_hold(r, args, policy.workspace)]
        with locked(self.path.with_suffix(".lock")):
            state = load_signed(self.path, self.key) if self.path.exists() else {"grants": {}, "rates": {}}
            t = now()
            updated = {}
            for rule in rules:
                limit, window = _parse_rate(rule.rate)
                # Stable across restarts and policy revisions; rule IDs are operator-owned.
                key = policy.name + ":" + rule.id
                hits = [v for v in state["rates"].get(key, []) if t - v < window]
                if len(hits) >= limit:
                    return Decision(THROTTLE, [rule.id], [f"rate limit {rule.rate} exceeded"], policy.source_digest)
                updated[key] = hits + [t]
            state["rates"].update(updated)
            save_signed(self.path, state, self.key)
        return None
