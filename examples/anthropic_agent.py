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
# See docs/enforcement.md: configure reviewer public keys and sign decisions externally.


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

# Disable automatic retries: each generation request gets one reservation.
client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], max_retries=0)
model = os.environ["MODEL"]  # configure this exact model's input/output prices in jackline.toml
input_bound = int(os.environ.get("INPUT_TOKEN_BOUND", "16000"))
output_bound = 1024
if policy.budget.max_cost_usd is not None and model not in policy.budget.prices:
    raise ValueError("Configure MODEL prices in jackline.toml before running this example")
grant = issue(rt.key, "acme-q3", ["fs.read", "email.send"], "15m", issued_by=os.environ.get("USER", "me"))
session = rt.session("Summarise research/acme_q3_notes.md and email equities-desk@firm.internal", grant, task_id="acme-q3")

messages = [{"role": "user", "content": session.task}]
while True:
    session.step()
    request = {"model": model, "tools": anthropic_tools(rt, TOOLS), "messages": messages}
    # Token counting is a separate provider API, not a generation call. Establish
    # a conservative complete-input bound; provider estimates may need headroom.
    count = client.messages.count_tokens(**request).input_tokens
    if count > input_bound:
        raise ValueError("Input exceeds the configured reservation; shorten the conversation")
    resp = session.call_model(lambda: client.messages.create(**request, max_tokens=output_bound),
                              model=model, input_tokens_bound=input_bound, output_tokens_bound=output_bound)
    if resp.usage.input_tokens > input_bound or resp.usage.output_tokens > output_bound:
        session.finish("halted", "provider usage exceeded reservation; investigate before continuing")
        raise RuntimeError("Provider exceeded declared bounds; a hard spend ceiling is not established")
    messages.append({"role": "assistant", "content": resp.content})
    results = anthropic_tool_results(session, resp, record_usage=False)  # ← Jackline decides every tool call here
    if not results:
        break
    messages.append({"role": "user", "content": results})

session.finish("completed")
print(next((b.text for b in resp.content if b.type == "text"), ""))
