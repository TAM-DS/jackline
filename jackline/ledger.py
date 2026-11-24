"""Append-only, hash-chained, HMAC-signed run ledger (JSON Lines).

Every entry carries the hash of the previous entry and an HMAC over its own
hash. Editing, deleting, inserting or reordering any entry breaks
verification. Truncating the *tail* is only detectable against an anchor, so
`head()` returns the latest hash for you to store somewhere else (a ticket,
a WORM bucket, a SIEM).
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Iterator

from .util import canonical, iso, now, redact, sha256, sign, verify_sig

GENESIS = "0" * 64


class Ledger:
    def __init__(self, path: str | Path, key: bytes, fsync: bool = True) -> None:
        self.path = Path(path)
        self.key = key
        self.fsync = fsync
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev = 0, GENESIS
        for e in read(self.path):
            self._seq, self._prev = e["seq"], e["hash"]

    def append(self, run_id: str, type_: str, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            body = {
                "seq": self._seq + 1,
                "ts": iso(now()),
                "run": run_id,
                "type": type_,
                "data": redact(data),
                "prev": self._prev,
            }
            h = sha256(canonical(body))
            entry = {**body, "hash": h, "sig": sign(self.key, h)}
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
                fh.flush()
                if self.fsync:
                    os.fsync(fh.fileno())
            self._seq, self._prev = body["seq"], h
            return entry

    def head(self) -> str:
        return self._prev


def read(path: str | Path) -> Iterator[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def verify(path: str | Path, key: bytes, anchor: str | None = None) -> tuple[bool, str, int, str]:
    """→ (ok, message, entries, head_hash)."""
    prev, seq, n = GENESIS, 0, 0
    try:
        for e in read(path):
            n += 1
            body = {k: e[k] for k in ("seq", "ts", "run", "type", "data", "prev")}
            if e["seq"] != seq + 1:
                return False, f"entry {n}: sequence gap/reorder (expected {seq + 1}, got {e['seq']})", n, prev
            if e["prev"] != prev:
                return False, f"entry {n}: chain broken — previous entry was removed or altered", n, prev
            if sha256(canonical(body)) != e["hash"]:
                return False, f"entry {n}: content was modified after it was written", n, prev
            if not verify_sig(key, e["hash"], e.get("sig", "")):
                return False, f"entry {n}: signature invalid — not written by this key", n, prev
            prev, seq = e["hash"], e["seq"]
    except (json.JSONDecodeError, KeyError) as exc:
        return False, f"entry {n}: unreadable ({exc})", n, prev
    if anchor and not prev.startswith(anchor):
        return False, f"head {prev[:16]} does not match anchor {anchor[:16]} — ledger truncated or replaced", n, prev
    return True, f"ledger intact: {n} entries, head {prev[:16]}", n, prev
