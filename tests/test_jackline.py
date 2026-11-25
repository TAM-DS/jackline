"""Jackline test suite — stdlib unittest, offline. `python -m unittest discover -s tests -v`"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jackline import BudgetExceeded, Policy, PolicyError, Runtime, RunSuspended, issue  # noqa: E402
from jackline import adapters, cli, ledger  # noqa: E402
from jackline.approvals import ApprovalError  # noqa: E402
from jackline.demo import POLICY_TOML, run_demo  # noqa: E402
from jackline.replay import replay  # noqa: E402
from jackline.util import redact  # noqa: E402

KEY = b"k" * 64

BASE_POLICY = """
[jackline]
name = "test"
default = "deny"
workspace = "."

[approvals]
timeout = "{timeout}"

[budget]
max_tool_calls = {max_calls}

[[rule]]
id = "no-creds"
tools = ["fs.*"]
effect = "deny"
reason = "creds"
[rule.when]
path_matches = ["*/.ssh/*", "*.pem"]

[[rule]]
id = "read-ws"
tools = ["fs.read"]
effect = "allow"
[rule.when]
path_within = ["ws"]

[[rule]]
id = "egress"
tools = ["web.*"]
effect = "deny"
[rule.when]
host_not_in = ["example.com"]

[[rule]]
id = "web"
tools = ["web.get"]
effect = "allow"
rate = "2/min"

[[rule]]
id = "pay"
tools = ["pay.send"]
effect = "approve"
approvers = ["cfo"]

[[rule]]
id = "pay-cap"
tools = ["pay.send"]
effect = "deny"
[rule.when]
arg_gt = {{ amount = 1000 }}
"""


def make_policy(tmp: Path, timeout: str = "5m", max_calls: int = 100) -> Policy:
    (tmp / "ws").mkdir(exist_ok=True)
    return Policy.from_toml(BASE_POLICY.format(timeout=timeout, max_calls=max_calls), base_dir=tmp)


class TmpCase(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    def runtime(self, **kw) -> Runtime:
        policy = kw.pop("policy", None) or make_policy(self.tmp, kw.pop("timeout", "5m"), kw.pop("max_calls", 100))
        rt = Runtime(policy, home=self.tmp / ".jackline", key=KEY, fsync=False, trusted_local_approvals=True, **kw)
        rt.register("fs.read", lambda path: f"contents of {path}")
        rt.register("web.get", lambda url: f"GET {url}")
        rt.register("pay.send", lambda to, amount: f"paid {amount} to {to}", side_effect=True)
        return rt

    def grant(self, scopes=("fs.read", "web.get", "pay.send"), ttl="10m", **kw):
        return issue(KEY, "t", list(scopes), ttl, "tester", **kw)


# ------------------------------------------------------------------ policy
class TestPolicy(TmpCase):
    def test_precedence_and_default_deny(self):
        p = make_policy(self.tmp)
        self.assertEqual(p.evaluate("fs.read", {"path": "ws/a.txt"}).effect, "allow")
        self.assertEqual(p.evaluate("fs.read", {"path": "ws/key.pem"}).effect, "deny")  # deny beats allow
        self.assertEqual(p.evaluate("fs.read", {"path": "/etc/passwd"}).effect, "deny")  # default
        self.assertEqual(p.evaluate("shell.exec", {"cmd": "ls"}).rules, [])
        self.assertEqual(p.evaluate("pay.send", {"to": "x", "amount": 10}).effect, "approve")
        self.assertEqual(p.evaluate("pay.send", {"to": "x", "amount": 5000}).effect, "deny")  # deny beats approve

    def test_path_traversal_and_symlink_cannot_escape(self):
        p = make_policy(self.tmp)
        self.assertEqual(p.evaluate("fs.read", {"path": "ws/../../etc/passwd"}).effect, "deny")
        (self.tmp / "secret").mkdir()
        os.symlink(self.tmp / "secret", self.tmp / "ws" / "link")
        self.assertEqual(p.evaluate("fs.read", {"path": "ws/link/x"}).effect, "deny")

    def test_host_suffix_matching_is_exact(self):
        p = make_policy(self.tmp)
        self.assertEqual(p.evaluate("web.get", {"url": "https://api.example.com/x"}).effect, "allow")
        self.assertEqual(p.evaluate("web.get", {"url": "https://example.com.evil.net/x"}).effect, "deny")
        self.assertEqual(p.evaluate("web.get", {"url": "https://notexample.com/"}).effect, "deny")

    def test_unknown_keys_fail_closed(self):
        for bad in ('[[rule]]\nid="x"\ntools=["a"]\neffect="deny"\n[rule.when]\npath_matchs=["*"]\n',
                    '[[rule]]\nid="x"\ntools=["a"]\neffect="block"\n',
                    '[[rule]]\nid="x"\ntools=["a"]\neffect="deny"\nwhen_typo=1\n',
                    '[polcy]\nx=1\n'):
            with self.subTest(bad=bad), self.assertRaises(PolicyError):
                Policy.from_toml(bad)

    def test_can_ever_run(self):
        p = make_policy(self.tmp)
        self.assertTrue(p.can_ever_run("fs.read"))
        self.assertFalse(p.can_ever_run("shell.exec"))

    def test_shipped_policies_lint(self):
        Policy.from_toml(POLICY_TOML)
        Policy.from_toml((ROOT / "jackline" / "starter.toml").read_text())
        self.assertEqual((ROOT / "examples" / "policies" / "capital-markets.toml").read_text().strip(),
                         POLICY_TOML.strip())


# ------------------------------------------------------------------- grants
class TestGrants(TmpCase):
    def test_grant_scope_expiry_and_tamper(self):
        g = self.grant(scopes=["fs.read"])
        self.assertIsNone(g.check(KEY, "fs.read", 0))
        self.assertIn("outside", g.check(KEY, "web.get", 0))
        g2 = self.grant(scopes=["fs.read"], ttl="1s")
        self.assertIn("expired", g2.check(KEY, "fs.read", 0, at=g2.expires_at + 1))
        g.scopes.append("pay.send")  # widen by hand
        self.assertIn("signature", g.check(KEY, "pay.send", 0))
        self.assertIn("signature", self.grant().check(b"other-key", "fs.read", 0))

    def test_wildcard_grants_refused(self):
        with self.assertRaises(ValueError):
            issue(KEY, "t", ["*"], "5m", "x")

    def test_runtime_requires_grant(self):
        rt = self.runtime()
        s = rt.session("t", grant=None)
        r = s.call("fs.read", {"path": "ws/a"})
        self.assertEqual(r.status, "denied")
        self.assertEqual(r.decision["rules"], ["no-grant"])

    def test_max_calls(self):
        rt = self.runtime()
        s = rt.session("t", self.grant(max_calls=1))
        self.assertTrue(s.call("fs.read", {"path": "ws/a"}).ok)
        self.assertIn("limit", s.call("fs.read", {"path": "ws/b"}).decision["reasons"][0])


# ------------------------------------------------------------------ runtime
class TestRuntime(TmpCase):
    def test_allow_executes_and_deny_never_executes(self):
        ran = []
        rt = self.runtime()
        rt.register("fs.read", lambda path: ran.append(path) or "ok")
        s = rt.session("t", self.grant())
        self.assertTrue(s.call("fs.read", {"path": "ws/a"}).ok)
        r = s.call("fs.read", {"path": "/home/u/.ssh/id_rsa"})
        self.assertEqual(r.status, "denied")
        self.assertIn("DENIED", r.message())
        self.assertEqual(ran, ["ws/a"])

    def test_rate_limit_throttles(self):
        rt = self.runtime()
        s = rt.session("t", self.grant())
        effects = [s.call("web.get", {"url": "https://example.com"}).decision["effect"] for _ in range(4)]
        self.assertEqual(effects, ["allow", "allow", "throttle", "throttle"])

    def test_budget_halts_and_stays_halted(self):
        rt = self.runtime(max_calls=2)
        s = rt.session("t", self.grant())
        s.call("fs.read", {"path": "ws/a"})
        s.call("fs.read", {"path": "ws/b"})
        with self.assertRaises(BudgetExceeded):
            s.call("fs.read", {"path": "ws/c"})
        with self.assertRaises(BudgetExceeded):
            s.call("fs.read", {"path": "ws/d"})
        self.assertEqual(s.status, "halted")

    def test_cost_budget(self):
        pol = Policy.from_toml('[budget]\nmax_cost_usd = 0.01\n[budget.prices.m]\ninput_per_mtok = 10.0\n'
                               'output_per_mtok = 10.0\n')
        rt = self.runtime(policy=pol)
        s = rt.session("t", self.grant())
        s.record_model("m", 500, 0)
        with self.assertRaises(BudgetExceeded):
            s.record_model("m", 1000, 0)

    def test_tool_exception_is_data(self):
        rt = self.runtime()
        rt.register("fs.read", lambda path: 1 / 0)
        r = rt.session("t", self.grant()).call("fs.read", {"path": "ws/a"})
        self.assertEqual(r.status, "error")
        self.assertIn("ZeroDivisionError", r.output)

    def test_unregistered_tool(self):
        rt = self.runtime()
        rt.tools.pop("fs.read")
        self.assertEqual(rt.session("t", self.grant()).call("fs.read", {"path": "ws/a"}).status, "error")


# ---------------------------------------------------------------- approvals
class TestApprovals(TmpCase):
    def test_callback_approve_and_deny(self):
        rt = self.runtime(approval_mode="callback", approver=lambda a: (a.args["amount"] < 100, "cfo", "ok"))
        s = rt.session("t", self.grant())
        self.assertTrue(s.call("pay.send", {"to": "v", "amount": 50}).ok)
        r = s.call("pay.send", {"to": "v", "amount": 500})
        self.assertEqual(r.status, "denied")
        self.assertIn("denied by cfo", r.message())

    def test_unauthorised_approver_rejected(self):
        rt = self.runtime(approval_mode="callback", approver=lambda a: (True, "intern", ""))
        with self.assertRaises(ApprovalError):
            rt.session("t", self.grant()).call("pay.send", {"to": "v", "amount": 50})

    def test_completed_call_replayed_after_suspend_resume(self):
        paid = []
        rt = self.runtime()
        rt.register("pay.send", lambda to, amount: paid.append(amount) or "paid", side_effect=True)
        g = self.grant()
        s = rt.session("t", g)
        with self.assertRaises(RunSuspended) as cm:
            s.call("pay.send", {"to": "v", "amount": 75}, call_id="pay-1")
        self.assertEqual(s.status, "suspended")
        self.assertEqual(paid, [])
        rt.approvals.resolve(cm.exception.approval_id, True, "cfo", "invoice matches")
        # simulate a crash: brand-new runtime object, resume from checkpoint
        rt2 = self.runtime()
        rt2.register("pay.send", lambda to, amount: paid.append(amount) or "paid", side_effect=True)
        s2 = rt2.resume(s.run_id, g)
        self.assertTrue(s2.call("pay.send", {"to": "v", "amount": 75}, call_id="pay-1").ok)
        self.assertTrue(s2.call("pay.send", {"to": "v", "amount": 75}, call_id="pay-1").ok)  # replayed
        self.assertEqual(paid, [75])

    def test_approval_bound_to_exact_arguments(self):
        rt = self.runtime()
        g = self.grant()
        s = rt.session("t", g)
        with self.assertRaises(RunSuspended) as cm:
            s.call("pay.send", {"to": "v", "amount": 75}, call_id="pay-1")
        rt.approvals.resolve(cm.exception.approval_id, True, "cfo")
        s2 = rt.resume(s.run_id, g)
        r = s2.call("pay.send", {"to": "attacker", "amount": 999}, call_id="pay-1")
        self.assertEqual(r.status, "denied")

    def test_hand_edited_approval_rejected(self):
        rt = self.runtime()
        s = rt.session("t", self.grant())
        with self.assertRaises(RunSuspended) as cm:
            s.call("pay.send", {"to": "v", "amount": 75})
        p = rt.approvals.root / f"{cm.exception.approval_id}.json"
        data = json.loads(p.read_text())
        data.update(status="approved", resolved_by="cfo")
        p.write_text(json.dumps(data))
        with self.assertRaises(ApprovalError):
            rt.approvals.get(cm.exception.approval_id)

    def test_timeout_fails_closed(self):
        rt = self.runtime(timeout="1ms", approval_mode="wait")
        r = rt.session("t", self.grant()).call("pay.send", {"to": "v", "amount": 75})
        self.assertEqual(r.status, "denied")
        self.assertIn("expired", r.message())

    def test_wait_mode_with_human_in_another_thread(self):
        rt = self.runtime(approval_mode="wait")
        s = rt.session("t", self.grant())

        def human():
            for _ in range(200):
                pend = rt.approvals.list("pending")
                if pend:
                    rt.approvals.resolve(pend[0].id, True, "cfo", "ok")
                    return
                time.sleep(0.01)
        threading.Thread(target=human).start()
        self.assertTrue(s.call("pay.send", {"to": "v", "amount": 75}).ok)


# ------------------------------------------------------------------- ledger
class TestLedger(TmpCase):
    def _run(self) -> Runtime:
        rt = self.runtime()
        s = rt.session("t", self.grant())
        s.call("fs.read", {"path": "ws/a"})
        s.call("fs.read", {"path": "/x/.ssh/id"})
        s.finish()
        return rt

    def test_verify_ok_and_detects_edit_delete_reorder(self):
        rt = self._run()
        path = rt.ledger.path
        self.assertTrue(ledger.verify(path, KEY)[0])
        lines = path.read_text().splitlines()
        for name, mutated in (
                ("edit", [lines[0].replace('"t"', '"T"')] + lines[1:]),
                ("delete", lines[:2] + lines[3:]),
                ("reorder", [lines[1], lines[0]] + lines[2:])):
            with self.subTest(name):
                path.write_text("\n".join(mutated) + "\n")
                self.assertFalse(ledger.verify(path, KEY)[0])
        path.write_text("\n".join(lines) + "\n")
        self.assertFalse(ledger.verify(path, b"wrong-key")[0])

    def test_anchor_detects_truncation(self):
        rt = self._run()
        head = rt.ledger.head()
        lines = rt.ledger.path.read_text().splitlines()
        rt.ledger.path.write_text("\n".join(lines[:-1]) + "\n")
        self.assertTrue(ledger.verify(rt.ledger.path, KEY)[0])  # chain alone can't see a cut tail
        self.assertFalse(ledger.verify(rt.ledger.path, KEY, anchor=head)[0])

    def test_secrets_redacted_in_ledger(self):
        rt = self.runtime()
        tok = "ghp_" + "a" * 36
        rt.session("t", self.grant()).call("web.get", {"url": "https://example.com", "token": "s3cret",
                                                       "body": f"use {tok}"})
        text = rt.ledger.path.read_text()
        self.assertNotIn("s3cret", text)
        self.assertNotIn(tok, text)

    def test_redact_helper(self):
        self.assertEqual(redact({"api_key": "x", "n": 1}), {"api_key": "[REDACTED]", "n": 1})


# ------------------------------------------------------------------- replay
class TestReplay(TmpCase):
    def test_replay_shows_drift(self):
        rt = self.runtime()
        s = rt.session("t", self.grant())
        s.call("fs.read", {"path": "ws/a"})
        s.call("fs.read", {"path": "/etc/hosts"})
        stricter = Policy.from_toml('[jackline]\ndefault="deny"\n', base_dir=self.tmp)
        rep = replay(rt.ledger.path, stricter)
        self.assertEqual(rep.total, 2)
        self.assertEqual(rep.counts(), {"allow→deny": 1})


# ----------------------------------------------------------------- adapters
class TestAdapters(TmpCase):
    def test_anthropic_tool_use_blocks(self):
        rt = self.runtime()
        s = rt.session("t", self.grant())
        resp = {"model": "claude", "usage": {"input_tokens": 10, "output_tokens": 5}, "content": [
            {"type": "text", "text": "reading"},
            {"type": "tool_use", "id": "tu_1", "name": "fs.read", "input": {"path": "ws/a"}},
            {"type": "tool_use", "id": "tu_2", "name": "fs.read", "input": {"path": "/x/.ssh/id"}}]}
        out = adapters.anthropic_tool_results(s, resp)
        self.assertEqual([o["tool_use_id"] for o in out], ["tu_1", "tu_2"])
        self.assertEqual([o["is_error"] for o in out], [False, True])
        self.assertEqual(s.state["tokens"], 15)

    def test_openai_tool_calls(self):
        rt = self.runtime()
        s = rt.session("t", self.grant())
        resp = {"model": "gpt", "usage": {"prompt_tokens": 3, "completion_tokens": 4}, "choices": [{"message": {
            "tool_calls": [{"id": "call_1", "function": {"name": "web.get", "arguments": '{"url": "https://evil.net"}'}}]}}]}
        out = adapters.openai_tool_messages(s, resp)
        self.assertEqual(out[0]["tool_call_id"], "call_1")
        self.assertIn("DENIED", out[0]["content"])

    def test_tool_list_filtering(self):
        rt = self.runtime()
        tools = [{"name": "fs.read"}, {"name": "shell.exec"}]
        self.assertEqual([t["name"] for t in adapters.anthropic_tools(rt, tools)], ["fs.read"])


# ---------------------------------------------------------------- mcp proxy
class TestMCPProxy(TmpCase):
    def test_proxy_filters_denies_and_forwards(self):
        pol = self.tmp / "p.toml"
        pol.write_text('[jackline]\ndefault="deny"\n'
                       '[[rule]]\nid="read"\ntools=["read_file"]\neffect="allow"\n'
                       '[[rule]]\nid="no-ssh"\ntools=["read_file"]\neffect="deny"\n[rule.when]\npath_matches=["*/.ssh/*"]\n'
                       '[[rule]]\nid="writes"\ntools=["write_file"]\neffect="approve"\n')
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "a.txt"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/h/.ssh/id"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "delete_repo", "arguments": {}}},
        ]
        stdin = "".join(json.dumps(m) + "\n" for m in msgs)
        env = {**os.environ, "JACKLINE_KEY": "test-key", "PYTHONPATH": str(ROOT)}
        proc = subprocess.run(
            [sys.executable, "-m", "jackline", "mcp-proxy", "--policy", str(pol), "--home", str(self.tmp / ".j"),
             "--", sys.executable, str(ROOT / "tests" / "fake_mcp_server.py")],
            input=stdin.encode(), capture_output=True, timeout=60, env=env, cwd=self.tmp)
        out = {m["id"]: m for m in map(json.loads, proc.stdout.decode().splitlines()) if "id" in m}
        self.assertEqual(out[1]["result"]["serverInfo"]["name"], "fake")
        self.assertEqual([t["name"] for t in out[2]["result"]["tools"]], ["read_file", "write_file"])  # delete hidden
        self.assertIn("upstream ran read_file", out[3]["result"]["content"][0]["text"])
        self.assertTrue(out[4]["result"]["isError"])
        self.assertTrue(out[5]["result"]["isError"])
        self.assertTrue(ledger.verify(self.tmp / ".j" / "ledger.jsonl", b"test-key")[0])


# ----------------------------------------------------------------- demo/cli
class TestDemoAndCLI(TmpCase):
    def test_demo_outcome(self):
        r = run_demo(io.StringIO(), home=self.tmp / "demo", color=False)
        self.assertEqual((r["credentials_read"], r["exfiltration"], r["trades"]), (0, 0, 0))
        self.assertTrue(r["ledger_ok"])
        self.assertIn("max_tool_calls", r["halted"])
        self.assertEqual(r["approvals"], [("trade.submit", "denied", "risk-desk"),
                                          ("email.send", "approved", "head-of-research")])

    def test_demo_never_wipes_foreign_directory(self):
        d = self.tmp / "precious"
        d.mkdir()
        (d / "thesis.docx").write_text("do not delete")
        with self.assertRaises(FileExistsError):
            run_demo(io.StringIO(), home=d, color=False)
        self.assertTrue((d / "thesis.docx").exists())
        run_demo(io.StringIO(), home=self.tmp / "demo2", color=False)
        run_demo(io.StringIO(), home=self.tmp / "demo2", color=False)  # re-running its own dir is fine

    def test_cli_check_exit_codes_and_init(self):
        pol = self.tmp / "jackline.toml"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["init", str(pol)]), 0)
            self.assertEqual(cli.main(["lint", str(pol)]), 0)
            self.assertEqual(cli.main(["check", "fs.read", "--policy", str(pol), "--arg", "path=README.md"]), 0)
            self.assertEqual(cli.main(["check", "fs.read", "--policy", str(pol), "--arg", "path=~/.ssh/id_rsa"]), 1)
            self.assertEqual(cli.main(["check", "shell.exec", "--policy", str(pol), "--arg", "cmd=ls"]), 3)
            bad = self.tmp / "bad.toml"
            bad.write_text('[[rule]]\nid="x"\ntools=["a"]\neffect="nope"\n')
            self.assertEqual(cli.main(["lint", str(bad)]), 2)

    def test_quickstart_example_runs(self):
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        out = subprocess.run([sys.executable, str(ROOT / "examples" / "quickstart.py")], capture_output=True,
                             text=True, env=env, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("refunded $40", out.stdout)
        self.assertIn("outside this task's grant", out.stdout)

    def test_core_makes_no_network_calls(self):
        offenders = []
        for p in (ROOT / "jackline").glob("*.py"):
            src = p.read_text()
            for mod in ("socket", "urllib.request", "http.client", "requests", "httpx", "aiohttp"):
                if f"import {mod}" in src or f"from {mod} " in src:
                    offenders.append(f"{p.name}:{mod}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
