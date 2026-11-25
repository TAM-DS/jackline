"""Regression tests for authorization, recovery, identity and accounting boundaries."""
import concurrent.futures
import io
import json
import multiprocessing
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from test_jackline import KEY, ROOT, TmpCase, make_policy
from jackline import BudgetExceeded, Policy, PolicyError, Runtime, RunSuspended, issue
from jackline import adapters, ledger
from jackline.approvals import ApprovalError
from jackline.mcp_proxy import MCPProxy
from jackline.util import digest


def race_call(home, run_id, grant_json, marker, ready, start):
    """Separate processes share a run and both try to execute the same call."""
    from pathlib import Path
    from jackline.grants import Grant
    rt = Runtime(Policy.from_dict({"jackline": {"default": "allow"}}), home=home, key=KEY)
    def effect(**args):
        with Path(marker).open("a") as fh:
            fh.write("executed\n")
        return "done"
    rt.register("effect", effect, side_effect=True)
    session = rt.resume(run_id, Grant.from_json(grant_json))
    ready.put(True)
    start.wait(10)
    session.call("effect", {}, "same")


class TestRecoveryAndAuthority(TmpCase):
    def pending(self, **kw):
        rt = self.runtime(**kw)
        grant = self.grant()
        session = rt.session("t", grant)
        with self.assertRaises(RunSuspended) as cm:
            session.call("pay.send", {"to": "v", "amount": 10}, "pay")
        rt.approvals.resolve(cm.exception.approval_id, True, "cfo")
        return rt, session, grant

    def test_resume_requires_original_grant(self):
        rt, s, g = self.pending()
        with self.assertRaises(ValueError):
            rt.resume(s.run_id)
        with self.assertRaises(ValueError):
            rt.resume(s.run_id, self.grant())

    def test_policy_change_invalidates_approval(self):
        rt, s, g = self.pending()
        rt.policy = Policy.from_dict({"jackline": {"default": "allow"}})
        r = rt.resume(s.run_id, g).call("pay.send", {"to": "v", "amount": 10}, "pay")
        self.assertEqual(r.status, "denied")

    def test_changed_workspace_invalidates_approval(self):
        rt, s, g = self.pending()
        rt.policy.workspace = self.tmp / "other-workspace"
        r = rt.resume(s.run_id, g).call("pay.send", {"to": "v", "amount": 10}, "pay")
        self.assertEqual(r.status, "denied")

    def test_in_memory_policy_mutation_invalidates_approval(self):
        rt, s, g = self.pending()
        rt.policy.approval_timeout_s = 600
        r = rt.resume(s.run_id, g).call("pay.send", {"to": "v", "amount": 10}, "pay")
        self.assertEqual(r.status, "denied")

    def test_same_run_reentrant_tool_fails_instead_of_deadlocking(self):
        rt, g = self.runtime(), self.grant()
        s = rt.session("t", g)
        rt.register("fs.read", lambda path: s.call("fs.read", {"path": path}, "nested"))
        result = s.call("fs.read", {"path": "ws/a"}, "outer")
        self.assertEqual(result.status, "error")
        self.assertIn("nested access", result.output)

    def test_expired_grant_cannot_resume_approved_call(self):
        rt, s, g = self.pending()
        with patch("jackline.grants.now", return_value=g.expires_at + 1):
            r = rt.resume(s.run_id, g).call("pay.send", {"to": "v", "amount": 10}, "pay")
        self.assertEqual(r.status, "denied")

    def test_approved_record_also_expires(self):
        rt, s, g = self.pending()
        a = rt.approvals.list()[0]
        with patch("jackline.approvals.now", return_value=a.expires_at + 1):
            r = rt.resume(s.run_id, g).call("pay.send", {"to": "v", "amount": 10}, "pay")
        self.assertEqual(r.status, "denied")

    def test_wall_budget_rechecked_after_approval(self):
        rt, s, g = self.pending()
        rt.policy.budget.max_wall_time_s = 1
        with patch("jackline.runtime.now", return_value=s.state["started_at"] + 2):
            with self.assertRaises(BudgetExceeded):
                rt.resume(s.run_id, g).call("pay.send", {"to": "v", "amount": 10}, "pay")

    def test_callback_cannot_outlive_grant(self):
        g = self.grant()
        def reviewer(a):
            # Move grant's clock forward during human review, not before proposal.
            clock.start()
            return True, "cfo", "reviewed"
        clock = patch("jackline.grants.now", return_value=g.expires_at + 1)
        rt = self.runtime(approval_mode="callback", approver=reviewer)
        try:
            r = rt.session("t", g).call("pay.send", {"to": "v", "amount": 10})
            self.assertEqual(r.status, "denied")
        finally:
            clock.stop()

    def test_crash_after_side_effect_never_retries(self):
        rt, g, effects = self.runtime(), self.grant(), []
        rt.register("fs.read", lambda path: effects.append(path) or "done")
        s = rt.session("t", g)
        append = rt.ledger.append
        def fail(run, kind, data):
            if kind == "tool.result":
                raise OSError("synthetic disk failure after external effect")
            return append(run, kind, data)
        with patch.object(rt.ledger, "append", side_effect=fail), self.assertRaises(OSError):
            s.call("fs.read", {"path": "ws/a"}, "same")
        rt2 = self.runtime()
        rt2.register("fs.read", lambda path: effects.append(path))
        r = rt2.resume(s.run_id, g).call("fs.read", {"path": "ws/a"}, "same")
        self.assertEqual(r.status, "uncertain")
        self.assertEqual(effects, ["ws/a"])

    def test_crash_before_side_effect_does_not_claim_success(self):
        rt, g, effects = self.runtime(), self.grant(), []
        rt.register("fs.read", lambda path: effects.append(path))
        s = rt.session("t", g)
        append = rt.ledger.append
        def fail(run, kind, data):
            if kind == "tool.intent":
                raise OSError("synthetic crash before invocation")
            return append(run, kind, data)
        with patch.object(rt.ledger, "append", side_effect=fail), self.assertRaises(OSError):
            s.call("fs.read", {"path": "ws/a"}, "same")
        self.assertEqual(rt.resume(s.run_id, g).call("fs.read", {"path": "ws/a"}, "same").status, "uncertain")
        self.assertEqual(effects, [])

    def test_concurrent_processes_do_not_duplicate_effects(self):
        rt = Runtime(Policy.from_dict({"jackline": {"default": "allow"}}), self.tmp / "runtime", key=KEY)
        g = issue(KEY, "task", ["effect"], "5m", "test")
        s = rt.session("task", g)
        ctx = multiprocessing.get_context("spawn")
        ready, start = ctx.Queue(), ctx.Event()
        marker = self.tmp / "effects"
        workers = [ctx.Process(target=race_call, args=(str(rt.home), s.run_id, g.to_json(), str(marker), ready, start)) for _ in range(2)]
        try:
            for w in workers:
                w.start()
            for _ in workers:
                self.assertTrue(ready.get(timeout=10))
            start.set()
            for w in workers:
                w.join(10)
                self.assertEqual(w.exitcode, 0)
        finally:
            for w in workers:
                if w.is_alive():
                    w.terminate()
                    w.join()
        self.assertEqual(marker.read_text(), "executed\n")
        self.assertTrue(ledger.verify(rt.ledger.path, KEY)[0])

    def test_grant_is_bound_to_task(self):
        rt, g = self.runtime(), self.grant()
        self.assertEqual(rt.session("unrelated", g).call("fs.read", {"path": "ws/a"}).status, "denied")
        self.assertTrue(rt.session("description", g, task_id="t").call("fs.read", {"path": "ws/a"}).ok)

    def test_grant_limit_survives_sessions_and_runtime_restart(self):
        rt, g = self.runtime(), self.grant(max_calls=1)
        self.assertTrue(rt.session("t", g).call("fs.read", {"path": "ws/a"}).ok)
        rt2 = self.runtime()
        self.assertEqual(rt2.session("t", g).call("fs.read", {"path": "ws/b"}).status, "denied")

    def test_grant_limit_atomic_between_sessions(self):
        rt, g = self.runtime(), self.grant(max_calls=1)
        sessions = [rt.session("t", g) for _ in range(5)]
        with concurrent.futures.ThreadPoolExecutor() as pool:
            results = list(pool.map(lambda s: s.call("fs.read", {"path": "ws/a"}).ok, sessions))
        self.assertEqual(sum(results), 1)

    def test_grant_limit_atomic_between_processes(self):
        rt = Runtime(Policy.from_dict({"jackline": {"default": "allow"}}), self.tmp / "runtime", key=KEY)
        g = issue(KEY, "task", ["effect"], "5m", "test", max_calls=1)
        sessions = [rt.session("task", g) for _ in range(2)]
        ctx = multiprocessing.get_context("spawn")
        ready, start = ctx.Queue(), ctx.Event()
        marker = self.tmp / "effects"
        workers = [ctx.Process(target=race_call, args=(str(rt.home), s.run_id, g.to_json(), str(marker), ready, start)) for s in sessions]
        try:
            for w in workers:
                w.start()
            for _ in workers:
                self.assertTrue(ready.get(timeout=10))
            start.set()
            for w in workers:
                w.join(10)
                self.assertEqual(w.exitcode, 0)
        finally:
            for w in workers:
                if w.is_alive():
                    w.terminate()
                    w.join()
        self.assertEqual(marker.read_text(), "executed\n")

    def test_approval_rule_rate_limit_survives_restart(self):
        p = Policy.from_dict({"rule": [{"id": "limited", "tools": ["pay.send"], "effect": "approve", "rate": "1/min"}]})
        rt = self.runtime(policy=p, approval_mode="callback", approver=lambda a: (True, "cfo", "ok"))
        self.assertTrue(rt.session("t", self.grant()).call("pay.send", {"to": "v", "amount": 1}).ok)
        rt2 = self.runtime(policy=p, approval_mode="callback", approver=lambda a: (True, "cfo", "ok"))
        r = rt2.session("t", self.grant()).call("pay.send", {"to": "v", "amount": 1})
        self.assertEqual(r.decision["effect"], "throttle")

    def test_allow_rate_applies_when_approve_rule_takes_precedence(self):
        p = Policy.from_dict({"rule": [{"id": "limited", "tools": ["pay.send"], "effect": "allow", "rate": "1/min"},
                                     {"id": "review", "tools": ["pay.send"], "effect": "approve"}]})
        rt = self.runtime(policy=p, approval_mode="callback", approver=lambda a: (True, "cfo", "ok"))
        s = rt.session("t", self.grant())
        self.assertTrue(s.call("pay.send", {"to": "v", "amount": 1}).ok)
        self.assertEqual(s.call("pay.send", {"to": "v", "amount": 1}).decision["effect"], "throttle")

    def test_multiple_rate_limits_consume_atomically(self):
        p = Policy.from_dict({"rule": [
            {"id": "a", "tools": ["x", "y"], "effect": "allow", "rate": "2/min"},
            {"id": "b", "tools": ["x"], "effect": "allow", "rate": "1/min"}]})
        rt = self.runtime(policy=p, require_grant=False)
        rt.register("x", lambda: "x")
        rt.register("y", lambda: "y")
        s = rt.session("rate")
        self.assertTrue(s.call("x").ok)
        self.assertEqual(s.call("x").decision["effect"], "throttle")
        self.assertTrue(s.call("y").ok)  # rejected x must not burn a's remaining slot

    def test_checkpoint_redacts_outputs_and_uses_private_modes(self):
        rt, g = self.runtime(), self.grant()
        rt.register("fs.read", lambda path: {"api_key": "synthetic-secret", "value": "public"})
        s = rt.session("t", g)
        self.assertEqual(s.call("fs.read", {"path": "ws/a"}, "one").output["api_key"], "synthetic-secret")
        p = s._state_path(rt.home, s.run_id)
        self.assertNotIn("synthetic-secret", p.read_text())
        for path in (p, rt.ledger.path, rt.authority.path):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(p.parent.stat().st_mode & 0o777, 0o700)
        r = rt.resume(s.run_id, g).call("fs.read", {"path": "ws/a"}, "one")
        self.assertEqual(r.output["api_key"], "[REDACTED]")

    def test_checkpoint_edit_fails_closed(self):
        rt, g = self.runtime(), self.grant()
        s = rt.session("t", g)
        p = s._state_path(rt.home, s.run_id)
        data = json.loads(p.read_text())
        data["state"]["tool_calls"] = -1000
        p.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            rt.resume(s.run_id, g)

    def test_tampered_authority_state_fails_closed(self):
        rt, g = self.runtime(), self.grant()
        rt.session("t", g).call("fs.read", {"path": "ws/a"})
        data = json.loads(rt.authority.path.read_text())
        data["state"]["grants"] = {}
        rt.authority.path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            rt.session("t", g).call("fs.read", {"path": "ws/b"})

    def test_ledger_rejects_tamper_before_append(self):
        rt = self.runtime()
        rt.ledger.append("test", "test", {"value": "original"})
        rt.ledger.path.write_text(rt.ledger.path.read_text().replace("original", "changed"))
        with self.assertRaises(ValueError):
            rt.ledger.append("test", "test", {})
        with self.assertRaises(ValueError):
            self.runtime()

    def test_different_ledger_instances_share_chain(self):
        rt = self.runtime()
        other = ledger.Ledger(rt.ledger.path, KEY)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            list(pool.map(lambda i: (rt.ledger if i % 2 else other).append("test", "event", {"i": i}), range(20)))
        self.assertTrue(ledger.verify(rt.ledger.path, KEY)[0])


class TestApprovalIdentity(TmpCase):
    def setUp(self):
        super().setUp()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.private = Ed25519PrivateKey.generate()
        self.secret = self.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())  # deadbolt:allow -- generated test key, not a literal credential
        public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        p = Policy.from_dict({"approvals": {"public_keys": {"cfo": public}},
            "rule": [{"id": "pay", "tools": ["pay.send"], "effect": "approve", "approvers": ["cfo"]}]})
        self.rt = Runtime(p, self.tmp / "runtime", key=KEY)
        self.effects = []
        self.rt.register("pay.send", lambda **args: self.effects.append(args) or "paid")
        self.g = issue(KEY, "task", ["pay.send"], "5m", "issuer")
        self.s = self.rt.session("task", self.g)
        with self.assertRaises(RunSuspended) as cm:
            self.s.call("pay.send", {"amount": 5}, "pay")
        self.aid = cm.exception.approval_id

    def test_identity_label_alone_is_not_authorization(self):
        with self.assertRaises(ApprovalError):
            self.rt.approvals.resolve(self.aid, True, "cfo")
        self.assertEqual(self.effects, [])

    def test_matching_private_key_authorizes_exact_call(self):
        self.rt.approvals.resolve(self.aid, True, "cfo", private_key=self.secret)
        self.assertTrue(self.rt.resume(self.s.run_id, self.g).call("pay.send", {"amount": 5}, "pay").ok)
        self.assertEqual(len(self.effects), 1)

    def test_wrong_signing_key_rejected(self):
        with self.assertRaises(ApprovalError):
            self.rt.approvals.resolve(self.aid, True, "cfo", private_key=b"x" * 32)

    def test_runtime_hmac_key_cannot_forge_human_decision(self):
        a = self.rt.approvals.get(self.aid)
        a.status, a.resolved_by, a.resolved_at = "approved", "cfo", a.requested_at
        self.rt.approvals._write(a)  # attacker possesses the runtime HMAC key
        with self.assertRaises(ApprovalError):
            self.rt.resume(self.s.run_id, self.g).call("pay.send", {"amount": 5}, "pay")

    def test_signed_approval_cannot_be_rebound_even_with_runtime_key(self):
        a = self.rt.approvals.resolve(self.aid, True, "cfo", private_key=self.secret)
        a.call_digest = digest({"tool": "pay.send", "args": {"amount": 500}})
        self.rt.approvals._write(a)
        with self.assertRaises(ApprovalError):
            self.rt.approvals.get(self.aid)

    def test_cli_signed_approval_is_accepted_by_runtime(self):
        from jackline import cli
        from contextlib import redirect_stdout
        private_file, policy_file = self.tmp / "reviewer.key", self.tmp / "review.toml"
        private_file.write_text(self.secret.hex())
        policy_file.write_text('[approvals.public_keys]\ncfo="' + self.rt.policy.approver_keys["cfo"] + '"\n')
        with patch.dict(os.environ, {"JACKLINE_KEY": KEY.decode()}), redirect_stdout(io.StringIO()):
            code = cli.main(["approvals", "approve", self.aid, "--by", "cfo", "--reason", "checked",
                             "--home", str(self.rt.home), "--policy", str(policy_file), "--signing-key", str(private_file)])
        self.assertEqual(code, 0)
        self.assertTrue(self.rt.resume(self.s.run_id, self.g).call("pay.send", {"amount": 5}, "pay").ok)


class TestModelAndValidation(TmpCase):
    def test_preflight_rejects_before_provider_invocation(self):
        p = Policy.from_dict({"budget": {"max_cost_usd": .01, "prices": {"m": {"input_per_mtok": 10, "output_per_mtok": 10}}}})
        s = self.runtime(policy=p).session("t", self.grant())
        calls = []
        with self.assertRaises(BudgetExceeded):
            s.call_model(lambda: calls.append(True), model="m", input_tokens_bound=1000, output_tokens_bound=1000)
        self.assertEqual(calls, [])

    def test_failed_provider_reservation_survives_restart(self):
        p = Policy.from_dict({"budget": {"max_model_calls": 1}})
        rt, g = self.runtime(policy=p), self.grant()
        s = rt.session("t", g)
        with self.assertRaises(ZeroDivisionError):
            s.call_model(lambda: 1 / 0, model="m", input_tokens_bound=1, output_tokens_bound=1)
        s2 = rt.resume(s.run_id, g)
        calls = []
        with self.assertRaises(BudgetExceeded):
            s2.call_model(lambda: calls.append(True), model="m", input_tokens_bound=1, output_tokens_bound=1)
        self.assertEqual(calls, [])

    def test_unknown_price_and_invalid_usage_rejected(self):
        s = self.runtime(policy=Policy.from_dict({"budget": {"max_cost_usd": 1}})).session("t", self.grant())
        with self.assertRaises(ValueError):
            s.call_model(lambda: self.fail("provider invoked"), model="unknown", input_tokens_bound=1, output_tokens_bound=1)
        for invalid in (-1, float("nan"), float("inf"), True, 1.5, "2"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                s.record_model("m", invalid, 0)

    def test_final_agent_response_usage_is_counted(self):
        rt = self.runtime()
        class Agent:
            def next_action(self, task, observations):
                return {"final": "done", "usage": {"model": "m", "input_tokens": 3, "output_tokens": 2}}
        self.assertEqual(rt.run_agent(Agent(), "t", self.grant()).state["tokens"], 5)

    def test_run_agent_requires_preflight_for_model_budget(self):
        rt = self.runtime(policy=Policy.from_dict({"budget": {"max_model_calls": 1}}))
        class Agent:
            def next_action(self, task, observations):
                raise AssertionError("unreserved model call")
        with self.assertRaises(ValueError):
            rt.run_agent(Agent(), "t", self.grant())

    def test_small_model_costs_are_not_rounded_to_zero(self):
        p = Policy.from_dict({"budget": {"max_cost_usd": 1.5e-8,
            "prices": {"m": {"input_per_mtok": .01, "output_per_mtok": .01}}}})
        s = self.runtime(policy=p).session("t", self.grant())
        self.assertEqual(s.call_model(lambda: "done", model="m", input_tokens_bound=1, output_tokens_bound=0), "done")
        with self.assertRaises(BudgetExceeded):
            s.call_model(lambda: self.fail("overspend"), model="m", input_tokens_bound=1, output_tokens_bound=0)

    def test_secret_objects_do_not_leak_through_repr(self):
        rt, g = self.runtime(), self.grant()
        class SecretObject:
            def __repr__(self):
                return "synthetic-secret-contents"
        rt.register("fs.read", lambda path: SecretObject())
        s = rt.session("t", g)
        s.call("fs.read", {"path": "ws/a"})
        self.assertNotIn("synthetic-secret-contents", s._state_path(rt.home, s.run_id).read_text())
        self.assertNotIn("synthetic-secret-contents", rt.ledger.path.read_text())

    def test_nested_unknown_policy_keys_and_bad_values_rejected(self):
        for data in ({"jackline": {"defalt": "allow"}}, {"approvals": {"timeot": "5m"}},
                     {"budget": {"prices": {"m": {"input_per_mtok": 1, "outpt_per_mtok": 1}}}},
                     {"budget": {"max_tokens": -1}}, {"budget": {"max_cost_usd": float("nan")}},
                     {"rule": [{"tools": ["x"], "effect": "deny", "when": {"path_within": "abc"}}]}):
            with self.subTest(data=data), self.assertRaises(PolicyError):
                Policy.from_dict(data)

    def test_bad_numeric_arguments_do_not_disable_deny_rules(self):
        p = make_policy(self.tmp)
        for args in ({}, {"amount": "bad"}, {"amount": float("nan")}, {"amount": True}):
            self.assertEqual(p.evaluate("pay.send", args).effect, "deny")

    def test_wildcard_variants_and_invalid_grants_rejected(self):
        for scope in ("fs.*", "fs.?", "fs.[ab]", ""):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                issue(KEY, "t", [scope], "5m", "issuer")
        for ttl in (-1, float("inf"), float("nan"), 0):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                issue(KEY, "t", ["fs.read"], ttl, "issuer")

    def test_invalid_json_never_reaches_tool(self):
        rt = self.runtime(policy=Policy.from_dict({"jackline": {"default": "allow"}}), require_grant=False)
        ran = []
        rt.register("x", lambda **args: ran.append(args))
        s = rt.session("t")
        for raw in ("{bad", "[]", "null"):
            response = {"choices": [{"message": {"tool_calls": [{"id": raw, "function": {"name": "x", "arguments": raw}}]}}]}
            self.assertIn("DENIED", adapters.openai_tool_messages(s, response)[0]["content"])
        self.assertEqual(ran, [])


class TestMCPHardening(TmpCase):
    def test_keyword_argument_cannot_replace_dispatch_name(self):
        rt = self.runtime(policy=Policy.from_dict({"rule": [{"tools": ["read_file"], "effect": "allow"}]}), require_grant=False)
        proxy = MCPProxy(rt, ["fake"], client_in=io.BytesIO(), client_out=io.BytesIO())
        forwarded = []
        proxy._forward = lambda name, args: forwarded.append((name, args)) or {"content": []}
        proxy._handle_call({"id": 1, "params": {"name": "read_file", "arguments": {"_n": "delete_repo"}}})
        self.assertEqual(forwarded, [("read_file", {"_n": "delete_repo"})])

    def test_tools_call_notification_is_never_forwarded(self):
        policy = self.tmp / "p.toml"
        policy.write_text('[jackline]\ndefault="deny"\n')
        msg = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_repo", "arguments": {}}}
        proc = subprocess.run([sys.executable, "-m", "jackline", "mcp-proxy", "--policy", str(policy),
            "--home", str(self.tmp / "runtime"), "--", sys.executable, str(ROOT / "tests/fake_mcp_server.py")],
            input=json.dumps(msg) + "\n", capture_output=True, text=True, timeout=10,
            env={**os.environ, "PYTHONPATH": str(ROOT), "JACKLINE_KEY": KEY.decode()})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("upstream ran", proc.stdout)
        self.assertIn("mcp.invalid_call", (self.tmp / "runtime/ledger.jsonl").read_text())

    def test_malformed_tool_params_never_forwarded(self):
        rt = self.runtime(require_grant=False)
        output = io.BytesIO()
        proxy = MCPProxy(rt, ["fake"], client_in=io.BytesIO(), client_out=output)
        proxy._forward = lambda *a: self.fail("malformed call forwarded")
        for params in ([], {"name": "read_file", "arguments": []}, {"name": 42}):
            proxy._handle_call({"id": 1, "params": params})
        self.assertEqual(len(output.getvalue().splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
