"""Minimal MCP stdio server used by the proxy tests (newline-delimited JSON-RPC)."""

import json
import sys

TOOLS = [
    {"name": "read_file", "description": "read a file", "inputSchema": {"type": "object"}},
    {"name": "write_file", "description": "write a file", "inputSchema": {"type": "object"}},
    {"name": "delete_repo", "description": "delete a repository", "inputSchema": {"type": "object"}},
]

for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    mid, method = msg.get("id"), msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fake", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        p = msg["params"]
        result = {"content": [{"type": "text", "text": f"upstream ran {p['name']} {json.dumps(p['arguments'], sort_keys=True)}"}]}
    elif mid is None:
        continue  # notification
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "nope"}}) + "\n")
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
    sys.stdout.flush()
