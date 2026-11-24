"""Wrapping a real Claude tool-use loop with Jackline.

Requires `pip install anthropic` and ANTHROPIC_API_KEY. Jackline itself has no
SDK dependency: the adapter works on the response object (or a plain dict).

    python examples/anthropic_agent.py
"""

import os
from pathlib import Path

import anthropic  # third-party; only this example needs it

from jackline import Policy, Runtime, issue
from jackline.adapters import anthropic_tool_results, anthropic_tools

# Copy examples/policies/capital-markets.toml to ./jackline.toml first; paths in rules resolve from its folder.
policy = Policy.load("jackline.toml")
rt = Runtime(policy, home=".jackline", approval_mode="wait")  # approve from another terminal:
#                                                                jackline approvals list / approve <id> --by you


@rt.tool("fs.read")
def fs_read(path: str) -> str:
    return Path(path).read_text()


@rt.tool("email.send", side_effect=True)
def email_send(to: str, subject: str, body: str) -> str:
    return f"(wire your mail client here) queued to {to}"


TOOLS = [
    {"name": "fs.read", "description": "Read a research file",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "email.send", "description": "Email a colleague",
     "input_schema": {"type": "object", "properties": {"to": {"type": "string"}, "subject": {"type": "string"},
                                                       "body": {"type": "string"}}, "required": ["to", "subject", "body"]}},
    {"name": "shell.exec", "description": "Run a shell command",  # hidden from the model: no rule allows it
     "input_schema": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}},
]

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
grant = issue(rt.key, "acme-q3", ["fs.read", "email.send"], "15m", issued_by=os.environ.get("USER", "me"))
session = rt.session("Summarise research/acme_q3_notes.md and email equities-desk@firm.internal", grant)

messages = [{"role": "user", "content": session.task}]
while True:
    session.step()
    resp = client.messages.create(model=os.environ.get("MODEL", "claude-sonnet-5-5"), max_tokens=1024,
                                  tools=anthropic_tools(rt, TOOLS), messages=messages)
    messages.append({"role": "assistant", "content": resp.content})
    results = anthropic_tool_results(session, resp)  # ← Jackline decides every tool call here
    if not results:
        break
    messages.append({"role": "user", "content": results})

session.finish("completed")
print(next((b.text for b in resp.content if b.type == "text"), ""))
