# Security policy

Jackline is a control layer, so we treat bypasses as the highest-severity bugs:

- a call executing without a valid grant (when grants are required)
- a call executing that the policy denies, or that needs approval but has none
- an approval being reused for different arguments, or accepted from an unlisted approver
- a ledger modification that `jackline ledger verify` does not detect
- a recognized credential pattern bypassing redaction in a ledger or checkpoint
- an execution repeated after a persisted invocation intent
- a grant limit reset by opening another run in the same runtime home

**Report privately:** Security → Advisories → Report a vulnerability on this repository. Please don't open a public issue.

Please use synthetic reproductions only. Never send real credentials or customer data.

**Out of scope by design** (see "Guarantees and honest limits" in the README): Jackline is not a sandbox for the
tools it lets run; ledger tail truncation is detected only against an external anchor; HMAC keys must be protected
by the operator. Authenticated reviewer decisions require separate protected Ed25519 private keys;
trusted-local demo approvals do not authenticate people. The runtime home and policies must not be
agent-writable. Full signed-state rollback and compromised operator keys are outside these local
controls. See [the enforcement contract](docs/enforcement.md) for recovery, model-budget,
filesystem and destination-idempotency requirements.
