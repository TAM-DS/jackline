# Security policy

Jackline is a control layer, so we treat bypasses as the highest-severity bugs:

- a call executing without a valid grant (when grants are required)
- a call executing that the policy denies, or that needs approval but has none
- an approval being reused for different arguments, or accepted from an unlisted approver
- a ledger modification that `jackline ledger verify` does not detect
- a raw credential being written to the ledger

**Report privately:** Security → Advisories → Report a vulnerability on this repository. Please don't open a public issue.

Please use synthetic reproductions only. Never send real credentials or customer data.

**Out of scope by design** (see "Guarantees and honest limits" in the README): Jackline is not a sandbox for the
tools it lets run; ledger tail truncation is detected only against an external anchor; HMAC keys must be protected
by the operator.
