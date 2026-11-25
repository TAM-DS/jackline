"""Generate an approver key OUTSIDE the runtime account/home.

    pip install 'jackline[approvals]'
    python examples/create_approver_key.py /private/reviewer/cfo.key

Prints only the public key. Keep the private file inaccessible to the agent
and runtime service account; configure the printed public key in policy.
"""
import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("path", type=Path)
args = parser.parse_args()
key = Ed25519PrivateKey.generate()
private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
fd = os.open(args.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, "w") as fh:
    fh.write(private.hex() + "\n")
    fh.flush()
    os.fsync(fh.fileno())
print(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
