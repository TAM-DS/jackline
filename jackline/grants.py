"""Task-scoped, expiring, signed grants — no standing authority.

The policy says what may *ever* run. A grant says what this particular task
may run, for how long, and how many times. Effective authority is the
intersection of the two. Grants are HMAC-signed so an agent (or a person
editing JSON) cannot widen its own scope.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .util import digest, iso, now, parse_duration, sign, verify_sig


@dataclass
class Grant:
    task_id: str
    scopes: list[str]
    issued_by: str
    issued_at: float
    expires_at: float
    max_calls: int | None = None
    note: str = ""
    grant_id: str = ""
    sig: str = ""

    def body(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("sig")
        d.pop("grant_id")
        return d

    def covers(self, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(tool, s) for s in self.scopes)

    def expired(self, at: float | None = None) -> bool:
        return (at if at is not None else now()) >= self.expires_at

    def check(self, key: bytes, tool: str, calls_used: int, at: float | None = None) -> str | None:
        """Return a denial reason, or None if the grant permits this call."""
        if not verify_sig(key, self.body(), self.sig) or self.grant_id != digest(self.body())[:16]:
            return "grant signature invalid — grant was altered or issued by another key"
        if self.expired(at):
            return f"grant expired at {iso(self.expires_at)}"
        if not self.covers(tool):
            return f"tool {tool!r} is outside this task's grant (scopes: {', '.join(self.scopes)})"
        if self.max_calls is not None and calls_used >= self.max_calls:
            return f"grant call limit reached ({self.max_calls})"
        return None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "Grant":
        return cls(**json.loads(text))

    @classmethod
    def load(cls, path: str | Path) -> "Grant":
        return cls.from_json(Path(path).read_text())


def issue(key: bytes, task_id: str, scopes: list[str], ttl: str | float, issued_by: str,
          max_calls: int | None = None, note: str = "", at: float | None = None) -> Grant:
    if not scopes:
        raise ValueError("a grant needs at least one scope")
    if any(s.strip() in ("*", "**") for s in scopes):
        raise ValueError("wildcard '*' grants are standing authority — list the tools the task needs")
    t = at if at is not None else now()
    g = Grant(task_id=task_id, scopes=list(scopes), issued_by=issued_by, issued_at=t,
              expires_at=t + parse_duration(ttl), max_calls=max_calls, note=note)
    g.grant_id = digest(g.body())[:16]
    g.sig = sign(key, g.body())
    return g
