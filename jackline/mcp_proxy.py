"""Drop-in MCP stdio proxy.

    MCP client (Claude Desktop, Cursor, an agent)  ⇄  jackline mcp-proxy  ⇄  upstream MCP server

Change one line in the client's MCP config — the server's `command` becomes
`jackline mcp-proxy ... -- <original command>` — and every `tools/call`
passes through the governed runtime: grant, policy, rate limit, human
approval (the proxy waits; approve from another terminal), budget, ledger.
`tools/list` responses are filtered so the model never sees tools the
policy can never run. All other JSON-RPC traffic is passed through untouched.

Transport: newline-delimited JSON-RPC over stdio (the MCP stdio transport).
Tool calls are serialised through the session; other traffic is concurrent.
"""

from __future__ import annotations

import itertools
import json
import subprocess
import sys
import threading
import uuid
from typing import IO, Any

from .grants import Grant
from .runtime import Runtime


class MCPProxy:
    def __init__(self, runtime: Runtime, upstream_cmd: list[str], grant: Grant | None = None,
                 prefix: str = "", client_in: IO[bytes] | None = None, client_out: IO[bytes] | None = None,
                 upstream_timeout_s: float = 600.0) -> None:
        if runtime.approval_mode == "suspend":
            runtime.approval_mode = "wait"  # a live MCP call must block until a human decides
        self.rt = runtime
        self.cmd = upstream_cmd
        self.prefix = prefix
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self.timeout = upstream_timeout_s
        self.session = runtime.session(f"mcp-proxy: {' '.join(upstream_cmd)}", grant,
                                       task_id=grant.task_id if grant else "mcp-proxy")
        self._out_lock = threading.Lock()
        self._upstream_lock = threading.Lock()
        self._call_lock = threading.Lock()
        self._ids = itertools.count(1)
        self._waiters: dict[str, tuple[threading.Event, dict[str, Any]]] = {}
        self._list_ids: set[Any] = set()
        self.proc: subprocess.Popen[bytes] | None = None

    # ------------------------------------------------------------- plumbing
    def _send_client(self, msg: dict[str, Any]) -> None:
        with self._out_lock:
            self.client_out.write((json.dumps(msg) + "\n").encode())
            self.client_out.flush()

    def _send_upstream(self, msg: dict[str, Any]) -> None:
        assert self.proc and self.proc.stdin
        with self._upstream_lock:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode())
            self.proc.stdin.flush()

    def _forward(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        uid = f"jackline-{uuid.uuid4().hex}"
        ev, box = threading.Event(), {}
        self._waiters[uid] = (ev, box)
        self._send_upstream({"jsonrpc": "2.0", "id": uid, "method": "tools/call",
                             "params": {"name": name, "arguments": arguments}})
        if not ev.wait(self.timeout):
            self._waiters.pop(uid, None)
            raise TimeoutError(f"upstream did not answer tools/call {name} within {self.timeout}s")
        msg = box["msg"]
        if "error" in msg:
            raise RuntimeError(msg["error"].get("message", "upstream error"))
        return msg.get("result", {})

    def _pump_upstream(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            mid = msg.get("id")
            if isinstance(mid, str) and mid in self._waiters and ("result" in msg or "error" in msg):
                ev, box = self._waiters.pop(mid)
                box["msg"] = msg
                ev.set()
                continue
            if mid in self._list_ids and "result" in msg:
                self._list_ids.discard(mid)
                tools = msg["result"].get("tools", [])
                msg["result"]["tools"] = [t for t in tools if self.rt.policy.can_ever_run(self.prefix + t.get("name", ""))]
                hidden = len(tools) - len(msg["result"]["tools"])
                if hidden:
                    self.rt.ledger.append(self.session.run_id, "mcp.tools_hidden", {"count": hidden})
            self._send_client(msg)

    # ----------------------------------------------------------- tool calls
    def _handle_call(self, msg: dict[str, Any]) -> None:
        cid = msg.get("id")
        params = msg.get("params", {})
        if not isinstance(params, dict) or not isinstance(params.get("name"), str) or not params["name"] or not isinstance(params.get("arguments", {}), dict):
            self._send_client({"jsonrpc": "2.0", "id": cid, "error": {"code": -32602, "message": "invalid tool parameters"}})
            return
        name = params["name"]
        args = params.get("arguments", {})
        tool = self.prefix + name
        if tool not in self.rt.tools:
            # Capture the dispatch name in a closure, never a keyword-overridable default.
            def forward(**arguments):
                return self._forward(name, arguments)
            self.rt.register(tool, forward, side_effect=True,
                             description="forwarded to upstream MCP server")
        try:
            with self._call_lock:
                res = self.session.call(tool, args, call_id=f"mcp{next(self._ids)}")
            if res.ok:
                result = res.output if isinstance(res.output, dict) else {
                    "content": [{"type": "text", "text": str(res.output)}]}
            else:
                result = {"content": [{"type": "text", "text": res.message()}], "isError": True}
        except Exception as exc:
            result = {"content": [{"type": "text", "text": f"[jackline] {exc}"}], "isError": True}
        self._send_client({"jsonrpc": "2.0", "id": cid, "result": result})

    # ------------------------------------------------------------------ run
    def serve(self) -> int:
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        pump = threading.Thread(target=self._pump_upstream, daemon=True)
        pump.start()
        workers: list[threading.Thread] = []
        try:
            for line in self.client_in:
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(msg, dict):
                    continue
                method = msg.get("method")
                if method == "tools/call" and ("id" not in msg or msg["id"] is None):
                    # Tool calls are requests. Never forward an ungated notification.
                    self.rt.ledger.append(self.session.run_id, "mcp.invalid_call", {"reason": "missing request id"})
                    continue
                if "id" in msg and (type(msg["id"]) not in (str, int)):
                    continue
                if method == "tools/call":
                    t = threading.Thread(target=self._handle_call, args=(msg,), daemon=True)
                    t.start()
                    workers.append(t)
                    continue
                if method == "tools/list" and "id" in msg:
                    self._list_ids.add(msg["id"])
                self._send_upstream(msg)
        finally:
            for t in workers:
                t.join(timeout=self.timeout)
            if self.proc.stdin:
                self.proc.stdin.close()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            pump.join(timeout=2)
            if self.session.status == "running":
                self.session.finish("completed")
        return 0
