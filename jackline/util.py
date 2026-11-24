"""Small shared helpers: canonical hashing, HMAC keys, redaction, durations."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - exercised on 3.10 only
    import tomli as _toml  # type: ignore[no-redef]


def load_toml(text: str) -> dict[str, Any]:
    return _toml.loads(text)


def canonical(obj: Any) -> str:
    """Deterministic JSON used for every hash and signature."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    return sha256(canonical(obj))


def sign(key: bytes, obj: Any) -> str:
    return hmac.new(key, canonical(obj).encode(), hashlib.sha256).hexdigest()


def verify_sig(key: bytes, obj: Any, sig: str) -> bool:
    return hmac.compare_digest(sign(key, obj), sig or "")


def now() -> float:
    return time.time()


def iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


_DUR = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?\s*$")


def parse_duration(value: str | int | float) -> float:
    """'90s' / '15m' / '2h' / '1d' / 30 → seconds."""
    if isinstance(value, (int, float)):
        return float(value)
    m = _DUR.match(value)
    if not m:
        raise ValueError(f"bad duration: {value!r}")
    n, unit = float(m.group(1)), m.group(2) or "s"
    return n * {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def load_or_create_key(path: Path, env: str = "JACKLINE_KEY") -> bytes:
    """HMAC key for grants and the ledger. Env var wins (use a KMS/secret manager in production);
    otherwise a 256-bit key is generated once and stored owner-read-only."""
    if os.environ.get(env):
        return os.environ[env].encode()
    if path.exists():
        return path.read_bytes().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


# ------------------------------------------------------------------ redaction
_SECRET_KEY = re.compile(r"(?i)(secret|token|passw|pwd|api[_\-]?key|authorization|cookie|credential|private[_\-]?key)")
_SECRET_VAL = re.compile(
    r"(AKIA[A-Z2-7]{16}|sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{36}|"
    r"xox[baprs]-[A-Za-z0-9\-]{10,}|eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def redact(obj: Any, _key: str = "") -> Any:
    """Mask credential-looking values before anything is written to the ledger."""
    if isinstance(obj, dict):
        return {k: redact(v, str(k)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v, _key) for v in obj]
    if isinstance(obj, str):
        if _key and _SECRET_KEY.search(_key) and obj:
            return "[REDACTED]"
        return _SECRET_VAL.sub("[REDACTED]", obj)
    return obj


def short(value: Any, n: int = 60) -> str:
    s = value if isinstance(value, str) else canonical(value)
    return s if len(s) <= n else s[: n - 1] + "…"
