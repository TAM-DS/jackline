# Enforcement and recovery contract

Jackline governs calls submitted to its APIs. Keep policy, the runtime home,
runtime key and tool implementations outside the agent's write authority.
Use a local POSIX filesystem on Linux/macOS, one durable runtime home for all
runs that share a grant or rate limit, and a single administrative trust domain.
Separate homes do not share counters. Network filesystems and distributed
deployments are not supported by the locking protocol.

## Task authority

`Runtime.session(description, grant, task_id="ticket-4471")` explicitly binds
the run to the grant's signed task identifier. If omitted, `task_id` defaults
to the description. The application must assign the correct task identifier;
Jackline cannot infer the business meaning of a natural-language task.

Grant scopes are exact tool names; wildcard variants are rejected. A valid
proposal reserves one grant use atomically across sessions/processes/restarts
sharing the home. Policy denials and throttles still consume this reservation.
The same run/call ID and argument digest reuse their reservation when resuming
an approval. Reusing an ID with different arguments is denied. A supplied grant
is enforced even in policy-only mode.

Run budgets persist across restarts. New runs have new run budgets; only grant
limits and rule rate limits are shared. Denied and throttled proposals count
against `max_tool_calls`. Pending approval resumes do not count twice.

## Authenticated human review

Install `pip install 'jackline[approvals]'`. Generate an Ed25519 private key in
the reviewer's protected environment, using `examples/create_approver_key.py`
if desired. Put only the public key in the runtime policy:

```toml
[approvals]
timeout = "5m"
[approvals.public_keys]
cfo = "REPLACE_WITH_64_HEX_CHARACTERS_FROM_KEY_GENERATION"

[[rule]]
id = "payments"
tools = ["pay.send"]
effect = "approve"
approvers = ["cfo"]
rate = "2/min"
```

The placeholder is intentionally invalid until replaced. From the reviewer's
environment, with access to the approval queue and the same trusted policy:

```bash
jackline approvals show APPROVAL_ID --home /runtime/.jackline --policy jackline.toml
jackline approvals approve APPROVAL_ID --by cfo --reason "invoice verified" \
  --signing-key /private/reviewer/cfo.key --policy jackline.toml --home /runtime/.jackline
```

`--by` selects a configured public key; it is not proof of identity. The CLI
needs the runtime HMAC key to read/write the queue envelope as well as the
separate approver private key to sign a decision. **Do not mount the approver
private key into the runtime or agent account.** This local-file review channel
is not an SSO service or remote approval broker. The signature establishes key
possession; the operator owns the mapping from a key to a person.

A decision signs the run, call ID, tool, argument digest, policy digest,
expiry, named reviewer and outcome. Even someone holding the runtime HMAC key
cannot forge a reviewer signature while the configured public keys and
verification code remain trusted. Grants and ledger entries still use HMAC;
they do not provide asymmetric issuer identity or non-repudiation.

After review, Jackline checks the grant, current policy, approval expiry and
run wall-time budget again. A policy change invalidates an existing approval. The digest covers effective
configuration, including the resolved workspace, rather than TOML text alone.
All matching allow/approve rule rate limits are checked and consumed together
immediately before invocation. A waiting approval does not reserve a rate slot.
An empty rule `approvers` list means any identity in the trusted public-key map;
a nonempty list further restricts it. There is one reviewer per decision, not
multi-signature approval.

`trusted_local_approvals=True` (CLI `--trusted-local`) deliberately bypasses
reviewer signature verification for offline demos and trusted local callbacks.
It is **not authenticated human identity or separation of duties**. Both the
runtime and review command must opt into this mode. Secure mode is the default;
without configured keys, approval-gated actions cannot be approved.

## Crash recovery and side effects

Before invoking a tool, Jackline writes and fsyncs an authenticated `uncertain`
execution record. After receiving the result, it persists the completed result.
Run locks serialize execution across threads and processes sharing a run ID.
A tool must not re-enter the same run; nested access fails instead of deadlocking.

| Recovery state | Behavior |
| --- | --- |
| No invocation intent | Reauthorization is required before execution. |
| Completed result | Replay the persisted, redacted result without invoking the tool. |
| Intent without completed result | Return `status="uncertain"`; do not automatically retry. |
| Same call ID, changed arguments | Deny. |
| Invalid or unsigned checkpoint | Refuse recovery. |

A crash can occur before the destination accepts an action or after it accepts
the action but before Jackline saves the result. The runtime cannot distinguish
those cases alone. This is **at-most-once invocation per run/call ID**, with
explicit uncertain outcomes; it is not unconditional exactly-once delivery.
For exactly-once business effects, the destination must provide a transactional
or idempotency contract. Include a stable destination idempotency key in the
approved arguments, query the destination after an uncertain outcome, and
reconcile before issuing a new call. A new run or new call ID is new authority,
not deduplication of an old business operation. A tool can also perform its own
internal retries; Jackline cannot deduplicate those.

Tool exceptions return an error and are cached, but do not prove that the
destination performed no action. Treat timeouts as potentially completed work.

## Model budgets

Use `session.call_model(invoke, model=..., input_tokens_bound=...,
output_tokens_bound=...)` to reserve the full upper-bound cost, tokens and one
model call **before** invoking the provider. Reservations survive crashes and
are not refunded, including failed requests. The ledger distinguishes
`model.reserved` from post-response `model.call` accounting. Use
`record_usage=False` on response adapters after a reservation to avoid counting
the same request twice.

The adapter must bound the entire input and enforce the provider's output
limit, including hidden/reasoning tokens and retries where applicable. Prices
must cover all billable usage. If that contract cannot be established, a hard
provider-spend ceiling cannot be claimed. No reservation wrapper can stop an
independent API call that bypasses it. A cost cap rejects unknown model prices;
negative, fractional and non-finite token counts are rejected.

`record_model` and the default response-adapter usage recording are
post-response accounting, not prevention of money already spent. `run_agent`
requires `model_limits` whenever model/token/cost budgets are configured.
Wall-time limits stop new actions at runtime boundaries; they do not kill an
already-running provider or tool. Tools must enforce their own timeouts.

## Storage and audit boundaries

Checkpoint, approval and authority state writes are atomic, fsynced and
owner-only (`0600`, directories `0700`). Persisted tool results are redacted;
the original caller may receive raw output, while replays receive the redacted
copy. Redaction is heuristic, not a guarantee that arbitrary sensitive text
can always be identified. Do not persist secrets as ordinary prose.

The ledger validates the existing chain before appending, using a process lock
and a fresh chain head. Append verification currently scans the whole ledger;
large deployments need rotation and external anchoring. An HMAC-key holder can
rewrite HMAC-protected records. Restoring a complete older signed state snapshot
or deleting runtime storage is outside these controls; protect backups and
anchor ledger heads externally. Do not allow the agent to read keys, edit
policy or write the runtime home.

Path checks use the policy workspace and `realpath`; tool implementations must
use that same workspace and prevent symlink changes between checking and open.
Host allowlists are not DNS pinning, redirect checks or SSRF protection. The MCP
proxy governs `tools/call`, drops call notifications lacking an ID, and forwards
other protocol methods. It does not govern arbitrary side effects of an MCP
server or provide an OS sandbox.

## Upgrade from 0.1.0 state

Old unsigned checkpoints and approvals without policy/signature bindings are
not silently trusted. Reconcile any previously started external work, archive
the old home, and start fresh runs in a new home with freshly issued grants.
Do not migrate an old execution cache and assume it supplies crash guarantees.
The demo and quickstart opt into simulated local approvals explicitly. Real
approval workflows must configure reviewer keys.
