"""Owner-only, durable local storage. Supported on local POSIX filesystems.

Locks coordinate threads and processes sharing one runtime home. They are not
distributed locks. The agent must not have filesystem access to this home.
"""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

from .util import sign, verify_sig

_locks: dict[str, threading.RLock] = {}
_guard = threading.Lock()
_held = threading.local()


def private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


@contextmanager
def locked(path: Path):
    private_dir(path.parent)
    identity = str(path.resolve())
    held = getattr(_held, "paths", set())
    if identity in held:
        raise RuntimeError("nested access to the same runtime lock is unsupported")
    with _guard:
        lock = _locks.setdefault(identity, threading.RLock())
    with lock:
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            _held.paths = held | {identity}
            yield
        finally:
            _held.paths = held
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def write_json(path: Path, value) -> None:
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(value, fh, sort_keys=True, allow_nan=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save_signed(path: Path, state: dict, key: bytes) -> None:
    write_json(path, {"state": state, "signature": sign(key, state)})


def load_signed(path: Path, key: bytes) -> dict:
    envelope = json.loads(path.read_text())
    if not isinstance(envelope, dict) or not isinstance(envelope.get("signature"), str):
        raise ValueError(f"invalid signed state: {path.name}; refusing recovery")
    state = envelope.get("state")
    if not isinstance(state, dict) or not verify_sig(key, state, envelope.get("signature", "")):
        raise ValueError(f"invalid signed state: {path.name}; refusing recovery")
    return state
