"""Replay: evals that grow out of the runtime.

Take real proposed calls from a ledger and re-decide them under a different
policy. Before you ship a policy change you see exactly which past actions
would now be allowed, blocked or sent to a human — measured on production
traffic, not on a synthetic test set.

Caveats (stated, not hidden): arguments are replayed in their *redacted*
ledger form, and grant/rate-limit state is not re-simulated — replay
measures the policy layer only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ledger import read
from .policy import Policy


@dataclass
class ReplayReport:
    total: int = 0
    unchanged: int = 0
    changes: list[dict[str, Any]] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for c in self.changes:
            k = f"{c['before']}→{c['after']}"
            out[k] = out.get(k, 0) + 1
        return out


def replay(ledger_path: str | Path, policy: Policy, run: str | None = None) -> ReplayReport:
    proposed: dict[tuple[str, str], dict[str, Any]] = {}
    decided: dict[tuple[str, str], tuple[str, list[str]]] = {}
    for e in read(ledger_path):
        if run and e["run"] != run:
            continue
        key = (e["run"], e["data"].get("call_id", ""))
        if e["type"] == "tool.proposed":
            proposed[key] = e["data"]
        elif e["type"] == "decision" and key not in decided:
            decided[key] = (e["data"]["effect"], e["data"].get("rules", []))
    rep = ReplayReport()
    for key, data in proposed.items():
        if key not in decided:
            continue
        before, rules = decided[key]
        if before == "throttle" or set(rules) & {"grant", "no-grant", "replay-mismatch"}:
            continue  # decided by grant / rate state, which replay does not re-simulate
        rep.total += 1
        d = policy.evaluate(data["tool"], data.get("args", {}))
        if d.effect == before:
            rep.unchanged += 1
        else:
            rep.changes.append({"run": key[0], "call_id": key[1], "tool": data["tool"], "args": data.get("args", {}),
                                "before": before, "after": d.effect, "rules": d.rules, "reasons": d.reasons})
    return rep
