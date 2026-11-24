"""Human approval queue.

An approval is bound to the *exact* call (a digest of tool + arguments). If
an agent proposes `trade.submit {qty: 100}` and a human approves it, that
approval cannot be reused for `{qty: 100000}`. Records are HMAC-signed, so a
hand-edited "approved" file is rejected. Unanswered requests expire to DENY.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .util import digest, iso, now, sign, verify_sig

PENDING, APPROVED, DENIED, EXPIRED = "pending", "approved", "denied", "expired"


@dataclass
class Approval:
    id: str
    run_id: str
    call_id: str
    tool: str
    args: dict[str, Any]  # redacted view for the human
    call_digest: str
    reasons: list[str]
    approvers: list[str]
    requested_at: float
    expires_at: float
    status: str = PENDING
    resolved_by: str | None = None
    resolved_at: float | None = None
    reason: str = ""
    sig: str = ""

    def body(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("sig")
        return d


class ApprovalError(Exception):
    pass


class ApprovalStore:
    def __init__(self, root: str | Path, key: bytes) -> None:
        self.root = Path(root)
        self.key = key
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, aid: str) -> Path:
        if not aid.isalnum():
            raise ApprovalError(f"bad approval id {aid!r}")
        return self.root / f"{aid}.json"

    def _write(self, a: Approval) -> None:
        a.sig = sign(self.key, a.body())
        tmp = self._path(a.id).with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(a), indent=2, sort_keys=True))
        os.replace(tmp, self._path(a.id))

    def request(self, run_id: str, call_id: str, tool: str, args_redacted: dict[str, Any], call_digest: str,
                reasons: list[str], approvers: list[str], timeout_s: float) -> Approval:
        aid = digest([run_id, call_id, call_digest])[:12]
        existing = self.get(aid, missing_ok=True)
        if existing:
            return existing
        t = now()
        a = Approval(id=aid, run_id=run_id, call_id=call_id, tool=tool, args=args_redacted,
                     call_digest=call_digest, reasons=reasons, approvers=approvers,
                     requested_at=t, expires_at=t + timeout_s)
        self._write(a)
        return a

    def get(self, aid: str, missing_ok: bool = False) -> Approval | None:
        p = self._path(aid)
        if not p.exists():
            if missing_ok:
                return None
            raise ApprovalError(f"no approval {aid}")
        a = Approval(**json.loads(p.read_text()))
        if not verify_sig(self.key, a.body(), a.sig):
            raise ApprovalError(f"approval {aid} failed signature check — file was edited by hand")
        if a.status == PENDING and now() >= a.expires_at:
            a.status, a.resolved_at, a.reason = EXPIRED, now(), "no decision before timeout (fail-closed)"
            self._write(a)
        return a

    def find(self, prefix: str) -> Approval:
        matches = [p.stem for p in self.root.glob("*.json") if p.stem.startswith(prefix)]
        if len(matches) != 1:
            raise ApprovalError(f"{len(matches)} approvals match {prefix!r}")
        return self.get(matches[0])  # type: ignore[return-value]

    def list(self, status: str | None = None) -> list[Approval]:
        out = []
        for p in sorted(self.root.glob("*.json")):
            try:
                a = self.get(p.stem)
            except ApprovalError:
                continue
            if a and (status is None or a.status == status):
                out.append(a)
        return sorted(out, key=lambda a: a.requested_at)

    def resolve(self, aid: str, approve: bool, by: str, reason: str = "") -> Approval:
        a = self.find(aid)
        if a.status != PENDING:
            raise ApprovalError(f"approval {a.id} is already {a.status}")
        if a.approvers and by not in a.approvers:
            raise ApprovalError(f"{by!r} is not an authorised approver for this action ({', '.join(a.approvers)})")
        a.status = APPROVED if approve else DENIED
        a.resolved_by, a.resolved_at, a.reason = by, now(), reason
        self._write(a)
        return a

    def wait(self, aid: str, poll_s: float = 0.25) -> Approval:
        while True:
            a = self.get(aid)
            assert a is not None
            if a.status != PENDING:
                return a
            time.sleep(min(poll_s, max(0.01, a.expires_at - now())))

    @staticmethod
    def describe(a: Approval) -> str:
        return (f"{a.id}  {a.status:8}  {a.tool}  requested {iso(a.requested_at)}"
                + (f"  by {a.resolved_by}" if a.resolved_by else ""))
