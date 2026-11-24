"""jackline — command line.

Exit codes: 0 success / allow · 1 deny or verification failure · 2 usage or runtime error · 3 requires approval
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .approvals import ApprovalError, ApprovalStore
from .grants import Grant, issue
from .ledger import read, verify
from .policy import Policy, PolicyError
from .replay import replay
from .util import iso, load_or_create_key, short


def _key(home: Path, key_file: Path | None = None) -> bytes:
    if key_file:
        return key_file.read_bytes().strip()
    return load_or_create_key(home / "jackline.key")


def _args(pairs: list[str], raw: str | None) -> dict:
    args: dict = json.loads(raw) if raw else {}
    for p in pairs:
        if "=" not in p:
            raise SystemExit(f"--arg expects key=value, got {p!r}")
        k, v = p.split("=", 1)
        try:
            args[k] = json.loads(v)
        except json.JSONDecodeError:
            args[k] = v
    return args


# ---------------------------------------------------------------- commands
def cmd_demo(a) -> int:
    from .demo import run_demo
    r = run_demo(sys.stdout, home=a.dir, color=False if a.no_color else None)
    return 0 if r["ledger_ok"] and r["credentials_read"] == 0 and r["exfiltration"] == 0 else 1


def cmd_init(a) -> int:
    if a.path.exists() and not a.force:
        print(f"{a.path} already exists (use --force)", file=sys.stderr)
        return 2
    a.path.write_text((Path(__file__).parent / "starter.toml").read_text())
    print(f"wrote {a.path} — edit the rules, then `jackline lint {a.path}`")
    return 0


def cmd_lint(a) -> int:
    p = Policy.load(a.policy)
    print(f"✔ {p.name}: {len(p.rules)} rules · default {p.default} · workspace {p.workspace} · digest {p.source_digest[:12]}")
    for r in p.rules:
        cond = ", ".join(sorted(r.when)) or "always"
        print(f"   {r.effect:8} {r.id:28} tools={','.join(r.tools):30} when={cond}"
              + (f" rate={r.rate}" if r.rate else "") + (f" approvers={','.join(r.approvers)}" if r.approvers else ""))
    return 0


def cmd_check(a) -> int:
    p = Policy.load(a.policy)
    d = p.evaluate(a.tool, _args(a.arg, a.json))
    if a.as_json:
        print(json.dumps(d.to_dict(), indent=2))
    else:
        print(f"{d.effect.upper():8} {a.tool}  rules={','.join(d.rules) or '-'}")
        for r in d.reasons:
            print(f"         {r}")
    return {"allow": 0, "deny": 1, "approve": 3}[d.effect]


def cmd_grant(a) -> int:
    g = issue(_key(a.home), a.task, a.scope, a.ttl, a.by, max_calls=a.max_calls, note=a.note)
    text = g.to_json()
    if a.output:
        a.output.write_text(text + "\n")
        print(f"grant {g.grant_id} → {a.output} (expires {iso(g.expires_at)})", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_approvals(a) -> int:
    store = ApprovalStore(a.home / "approvals", _key(a.home))
    try:
        if a.action == "list":
            items = store.list(None if a.status == "all" else a.status)
            if not items:
                print(f"no {a.status} approvals")
            for x in items:
                print(store.describe(x))
                print(f"           args: {short(x.args, 100)}")
                print(f"           why:  {'; '.join(x.reasons)}"
                      + (f"   approvers: {', '.join(x.approvers)}" if x.approvers else ""))
            return 0
        if a.action == "show":
            x = store.find(a.id)
            print(json.dumps({k: v for k, v in x.__dict__.items() if k != "sig"}, indent=2, default=str))
            return 0
        by = a.by or os.environ.get("USER", "unknown")
        x = store.resolve(a.id, a.action == "approve", by, a.reason)
        print(f"{x.id} {x.status} by {x.resolved_by}")
        return 0
    except ApprovalError as e:
        print(f"jackline: {e}", file=sys.stderr)
        return 2


def cmd_ledger(a) -> int:
    key_file = a.key_file or a.ledger.parent / "jackline.key"
    if a.action == "verify":
        ok, msg, _, head = verify(a.ledger, _key(a.ledger.parent, key_file), a.anchor)
        print(("✔ " if ok else "✘ ") + msg)
        if ok:
            print(f"  anchor this head somewhere immutable: {head}")
        return 0 if ok else 1
    entries = [e for e in read(a.ledger) if not a.run or e["run"] == a.run]
    for e in entries[-a.tail:] if a.tail else entries:
        d = e["data"]
        detail = d.get("tool") or d.get("model") or d.get("task") or d.get("limit") or ""
        extra = d.get("effect") or d.get("status") or ""
        print(f"{e['seq']:>5} {e['ts']} {e['run']} {e['type']:18} {short(detail, 40):40} {extra}")
    return 0


def cmd_replay(a) -> int:
    rep = replay(a.ledger, Policy.load(a.policy), a.run)
    if a.as_json:
        print(json.dumps({"total": rep.total, "unchanged": rep.unchanged, "changes": rep.changes}, indent=2,
                         default=str))
    else:
        print(f"replayed {rep.total} past decisions against {a.policy}: {rep.unchanged} unchanged, "
              f"{len(rep.changes)} would change")
        for k, v in sorted(rep.counts().items()):
            print(f"   {k:20} {v}")
        for c in rep.changes[:50]:
            print(f"   {c['before']:>8} → {c['after']:8} {c['tool']:14} {short(c['args'], 60)}  {','.join(c['rules'])}")
    return 1 if (a.fail_on_change and rep.changes) else 0


def cmd_mcp_proxy(a) -> int:
    from .mcp_proxy import MCPProxy
    from .runtime import Runtime
    cmd = a.command[1:] if a.command and a.command[0] == "--" else a.command
    if not cmd:
        print("usage: jackline mcp-proxy --policy P [--grant G] -- <upstream command ...>", file=sys.stderr)
        return 2
    rt = Runtime(Policy.load(a.policy), home=a.home, require_grant=bool(a.grant) or a.require_grant,
                 approval_mode="wait")
    grant = Grant.load(a.grant) if a.grant else None
    return MCPProxy(rt, cmd, grant=grant, prefix=a.prefix).serve()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jackline", description="Governed runtime for AI agents. "
                                                              "Clip in. Work freely. Never go overboard.")
    p.add_argument("--version", action="version", version=f"jackline {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    home = {"type": Path, "default": Path(os.environ.get("JACKLINE_HOME", ".jackline"))}

    d = sub.add_parser("demo", help="rogue-agent scenario, no API key needed")
    d.add_argument("--dir", type=Path, help="workspace for the demo (default: a new temp dir)")
    d.add_argument("--no-color", action="store_true")
    d.set_defaults(func=cmd_demo)

    i = sub.add_parser("init", help="write a starter policy")
    i.add_argument("path", nargs="?", type=Path, default=Path("jackline.toml"))
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    lt = sub.add_parser("lint", help="validate a policy and list its rules")
    lt.add_argument("policy", type=Path)
    lt.set_defaults(func=cmd_lint)

    c = sub.add_parser("check", help="decide one call against a policy (great for policy unit tests in CI)")
    c.add_argument("tool")
    c.add_argument("--policy", type=Path, default=Path("jackline.toml"))
    c.add_argument("--arg", action="append", default=[], help="key=value (JSON values allowed); repeatable")
    c.add_argument("--json", help="arguments as a JSON object")
    c.add_argument("--as-json", action="store_true")
    c.set_defaults(func=cmd_check)

    g = sub.add_parser("grant", help="issue a task-scoped, expiring, signed grant")
    g.add_argument("--task", required=True)
    g.add_argument("--scope", action="append", required=True, help="tool glob; repeatable")
    g.add_argument("--ttl", default="15m")
    g.add_argument("--by", required=True, help="who is granting this authority")
    g.add_argument("--max-calls", type=int)
    g.add_argument("--note", default="")
    g.add_argument("--home", **home)
    g.add_argument("--output", "-o", type=Path)
    g.set_defaults(func=cmd_grant)

    ap = sub.add_parser("approvals", help="human approval queue")
    ap.add_argument("action", choices=["list", "show", "approve", "deny"])
    ap.add_argument("id", nargs="?")
    ap.add_argument("--status", default="pending", choices=["pending", "approved", "denied", "expired", "all"])
    ap.add_argument("--by")
    ap.add_argument("--reason", default="")
    ap.add_argument("--home", **home)
    ap.set_defaults(func=cmd_approvals)

    lg = sub.add_parser("ledger", help="verify or show the signed run ledger")
    lg.add_argument("action", choices=["verify", "show"])
    lg.add_argument("ledger", type=Path, nargs="?", default=Path(home["default"]) / "ledger.jsonl")
    lg.add_argument("--key-file", type=Path)
    lg.add_argument("--anchor", help="expected head hash (prefix ok) — detects tail truncation")
    lg.add_argument("--run")
    lg.add_argument("--tail", type=int)
    lg.set_defaults(func=cmd_ledger)

    rp = sub.add_parser("replay", help="re-decide past calls under a new policy (evals from real traffic)")
    rp.add_argument("ledger", type=Path)
    rp.add_argument("--policy", type=Path, required=True)
    rp.add_argument("--run")
    rp.add_argument("--as-json", action="store_true")
    rp.add_argument("--fail-on-change", action="store_true", help="exit 1 if any decision would change")
    rp.set_defaults(func=cmd_replay)

    mp = sub.add_parser("mcp-proxy", help="govern any MCP server: jackline mcp-proxy --policy P -- <cmd>")
    mp.add_argument("--policy", type=Path, required=True)
    mp.add_argument("--grant", type=Path)
    mp.add_argument("--require-grant", action="store_true")
    mp.add_argument("--prefix", default="", help="prefix tool names for policy matching, e.g. 'github.'")
    mp.add_argument("--home", **home)
    mp.add_argument("command", nargs=argparse.REMAINDER)
    mp.set_defaults(func=cmd_mcp_proxy)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd == "approvals" and a.action != "list" and not a.id:
        print("jackline: approvals show/approve/deny need an approval id", file=sys.stderr)
        return 2
    try:
        return a.func(a)
    except PolicyError as e:
        print(f"jackline: policy error: {e}", file=sys.stderr)
        return 2
    except (FileNotFoundError, FileExistsError, ValueError) as e:
        print(f"jackline: {e}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        return 130
