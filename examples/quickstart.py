"""Jackline in ~30 lines — runs offline: `python examples/quickstart.py`.

Wrap your own tools, issue a task-scoped grant, and let the runtime decide.
"""

import tempfile
from pathlib import Path

from jackline import Policy, Runtime, issue

POLICY = """
[jackline]
name = "quickstart"
default = "deny"

[[rule]]
id = "read-docs"
tools = ["docs.read"]
effect = "allow"
[rule.when]
path_within = ["docs"]

[[rule]]
id = "refunds-need-a-human"
tools = ["billing.refund"]
effect = "approve"
"""

home = Path(tempfile.mkdtemp())
(home / "docs").mkdir()
(home / "docs" / "faq.md").write_text("Refunds are allowed within 30 days.")



def support_lead(approval):
    """Stands in for a human. In production: `jackline approvals approve <id> --by <you>`."""
    ok = approval.args["amount"] <= 50
    return ok, "support-lead", "within refund policy" if ok else "over the $50 agent limit"


rt = Runtime(Policy.from_toml(POLICY, base_dir=home), home=home / ".jackline",
             approval_mode="callback", approver=support_lead)


@rt.tool("docs.read")
def read_doc(path: str) -> str:
    return (home / path).read_text()


@rt.tool("billing.refund", side_effect=True)
def refund(order: str, amount: float) -> str:
    return f"refunded ${amount} on {order}"


grant = issue(rt.key, "ticket-4471", ["docs.read", "billing.refund"], "10m", issued_by="support-lead")
session = rt.session("handle ticket 4471", grant)

for tool, args in [("docs.read", {"path": "docs/faq.md"}),
                   ("docs.read", {"path": "/etc/passwd"}),
                   ("billing.refund", {"order": "A-1", "amount": 40}),
                   ("billing.refund", {"order": "A-1", "amount": 4000}),
                   ("db.drop_table", {"table": "orders"})]:
    print(f"{tool:16} {str(args):40} → {session.call(tool, args).message()}")

session.finish()
print(f"\nledger: {rt.ledger.path}")
