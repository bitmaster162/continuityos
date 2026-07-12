"""continuity — AI Agent Governance Gateway CLI.

  continuity init                         # create ledger + default policy
  continuity preflight shell "<cmd>"      # decide without running
  continuity run exec  -- <cmd...>        # argv-only (safe); rejects shell operators
  continuity run shell -- <cmd...>        # real shell (&&,|,>,$()) — mediated, stricter
  continuity audit                        # show + verify the audit ledger
"""
from __future__ import annotations
import argparse, glob, json, os, sys, subprocess, shlex, re, time
from ..db import context_fingerprint, resolve_memory_db
from .spec import ActionSpec
from .engine import preflight
from .classifier import extract_candidate_paths
from .ledger import Ledger
from .policy import PolicyError, default_policy, discover_policy, load_policy

HOME = os.path.expanduser("~/.continuityos")
LEDGER = os.path.join(HOME, "ledger.db")
POLICY = os.path.join(HOME, "policy.yaml")
POLICY_JSON = os.path.join(HOME, "policy.json")
EXIT_DRY_RUN_ONLY = 3
EXIT_RECEIPT_FAILURE = 4

def _paths_from(cmd: str):
    return extract_candidate_paths(cmd)

def _context(db=None):
    # canon-aware decisions: use the local continuity memory if present
    try:
        resolved = resolve_memory_db(db, default=os.path.join(HOME, "memory.db"))
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}", None
    mdb = resolved["path"]
    if not os.path.isfile(mdb):
        if resolved["configured"]:
            return (
                None,
                f"FileNotFoundError: configured memory database not found: {mdb}",
                {**resolved, "status": "missing"},
            )
        return None, None, {**resolved, "status": "absent"}
    try:
        # Validate the configured artifact before Memory/Store can initialize or
        # migrate it, then bind the post-open logical state used by the decision.
        context_fingerprint(mdb)
        from ..continuity import Continuity
        context = Continuity(db=mdb)
        identity = context_fingerprint(mdb)
        identity["source"] = resolved["source"]
        identity["status"] = "ready"
        context._context_source = resolved["source"]
        return context, None, identity
    except Exception as exc:
        return (
            None,
            f"{type(exc).__name__}: {exc}",
            {**resolved, "status": "invalid"},
        )

def _decide(cmd: str, tool="shell", agent="cli", args=None, paths=None,
            cwd=None, db=None):
    spec = ActionSpec(
        tool=tool,
        command=cmd,
        args=list(args or []),
        paths=list(paths) if paths is not None else _paths_from(cmd),
        agent=agent,
        cwd=os.getcwd() if cwd is None else cwd,
    )
    try:
        pol = load_policy(discover_policy(HOME))
    except (PolicyError, OSError) as exc:
        pol = default_policy()
        spec.meta["policy_error"] = f"{type(exc).__name__}: {exc}"
    context, context_error, _context_identity = _context(db)
    if context_error:
        spec.meta["context_error"] = context_error
    with Ledger(LEDGER) as led:
        result = preflight(spec, policy=pol, ledger=led, context=context)
    return result, spec


def _materialize_rollback(result) -> bool:
    """Create the declared local snapshot immediately before approved execution."""
    plan = result.get("rollback_plan") or {}
    if not plan.get("snapshot_required"):
        return True
    from .rollback import snapshot
    expanded_targets = list(plan.get("targets") or [])
    magic_targets = [target for target in expanded_targets if glob.has_magic(target)]
    if magic_targets:
        # Python glob semantics are not identical to cmd/PowerShell/POSIX shell
        # quoting and escaping. Do not issue a receipt for a different target set.
        print("\n[HELD] Shell wildcard rollback targets are unsupported; command was not executed.")
        for target in magic_targets:
            print("  -", target)
        plan.update({
            "snapshot_status": "failed",
            "snapshot_errors": [{
                "error": "wildcard targets cannot be bound to a deterministic snapshot",
                "paths": magic_targets,
            }],
            "restorable": False,
        })
        return False
    snap = snapshot(
        list(dict.fromkeys(expanded_targets)),
        allow_missing_files=bool(plan.get("allow_missing_files")),
    )
    plan.update({
        "snapshot_id": snap["id"],
        "files_saved": snap["saved"],
        "restorable": snap["restorable"],
        "snapshot_errors": snap.get("errors", []),
        "materialized_targets": expanded_targets,
        "restore_cmd": f"continuity rollback {snap['id']}",
        "snapshot_status": "materialized" if snap["restorable"] else "failed",
    })
    with Ledger(LEDGER) as led:
        receipt_hash = led.append("rollback_snapshot", {
            "preflight_hash": result.get("ledger_hash"),
            "action": result.get("action"),
            "rollback_plan": plan,
        })
    plan["receipt_hash"] = receipt_hash
    if not snap["restorable"]:
        print("\n[HELD] Required local snapshot could not be completed; command was not executed.")
        for error in snap.get("errors", []):
            print("  -", error.get("path"), error.get("error"))
        return False
    print("  rollback:", plan["restore_cmd"])
    return True


def _rollback_receipt(result):
    plan = result.get("rollback_plan") or {}
    if not plan.get("snapshot_required"):
        return {"required": False, "status": "not_required"}
    return {
        "required": True,
        "status": (
            "materialized"
            if plan.get("restorable") and plan.get("receipt_hash")
            else "failed"
        ),
        "receipt_hash": plan.get("receipt_hash"),
        "snapshot_id": plan.get("snapshot_id"),
        "restorable": bool(plan.get("restorable")),
        "errors": list(plan.get("snapshot_errors") or []),
    }


def _append_execution(kind, result, rollback_receipt, **fields):
    payload = {
        "preflight_hash": result.get("ledger_hash"),
        "action": result.get("action"),
        "rollback_receipt": rollback_receipt,
    }
    payload.update(fields)
    with Ledger(LEDGER) as led:
        return led.append(kind, payload)


def _write_receipt_failure_fallback(
    result, rollback_receipt, started_hash, terminal_kind,
    process_exit_code, receipt_error, execution_error=None,
):
    """Durable local ambiguity marker when the primary terminal ledger append fails."""
    payload = {
        "status": (
            "EXECUTED_BUT_RECEIPT_FAILED"
            if process_exit_code is not None
            else "EXECUTION_OUTCOME_RECEIPT_FAILED"
        ),
        "terminal_kind": terminal_kind,
        "preflight_hash": result.get("ledger_hash"),
        "action": result.get("action"),
        "rollback_receipt": rollback_receipt,
        "execution_started_hash": started_hash,
        "process_exit_code": process_exit_code,
        "receipt_error_type": type(receipt_error).__name__,
        "receipt_error": str(receipt_error),
        "execution_error": execution_error,
        "ts": time.time(),
        "instruction": "Do not retry blindly; reconcile the side effect and ledger first.",
    }
    path = LEDGER + ".receipt_failures.jsonl"
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def _handle_terminal_receipt_failure(
    result, rollback_receipt, started_hash, terminal_kind,
    process_exit_code, receipt_error, execution_error=None,
):
    fallback = None
    fallback_error = None
    try:
        fallback = _write_receipt_failure_fallback(
            result,
            rollback_receipt,
            started_hash,
            terminal_kind,
            process_exit_code,
            receipt_error,
            execution_error=execution_error,
        )
    except Exception as exc:
        fallback_error = f"{type(exc).__name__}: {exc}"
    status = (
        "EXECUTED_BUT_RECEIPT_FAILED"
        if process_exit_code is not None
        else "EXECUTION_OUTCOME_RECEIPT_FAILED"
    )
    print(
        f"\n[CRITICAL] {status}. Do not retry blindly; "
        "reconcile the side effect and ledger first."
    )
    print(f"  receipt error: {type(receipt_error).__name__}: {receipt_error}")
    if fallback:
        print(f"  fallback ambiguity journal: {fallback}")
    elif fallback_error:
        print(f"  fallback journal also failed: {fallback_error}")
    return EXIT_RECEIPT_FAILURE


def _execution_binding_error(cmd: str, mode: str, result, argv) -> str:
    preflight_hash = result.get("ledger_hash")
    if not isinstance(preflight_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", preflight_hash):
        return "approved execution has no full preflight ledger hash"
    action = result.get("action")
    if not isinstance(action, dict):
        return "approved execution has no typed action receipt"
    expected_tool = "shell" if mode == "shell" else "exec"
    if action.get("tool") != expected_tool:
        return f"preflighted tool {action.get('tool')!r} does not match execution mode {mode!r}"
    if action.get("command") != cmd:
        return "execution command differs from the preflighted action"
    if mode == "exec" and action.get("args") != list(argv):
        return "execution argv differs from the preflighted argument vector"
    action_cwd = action.get("cwd")
    if not isinstance(action_cwd, str) or not action_cwd:
        return "preflighted action has no authoritative execution cwd"
    if not os.path.isabs(os.path.expandvars(os.path.expanduser(action_cwd))):
        return "preflighted action cwd is not absolute"
    assessed_cwd = os.path.normcase(os.path.realpath(os.path.abspath(action_cwd)))
    execution_cwd = os.path.normcase(os.path.realpath(os.path.abspath(os.getcwd())))
    if assessed_cwd != execution_cwd:
        return "execution cwd differs from the preflighted action"
    try:
        with Ledger(LEDGER) as ledger:
            verification = ledger.verify()
            if not verification.get("ok"):
                return "execution ledger failed hash-chain verification"
            event = ledger.event(preflight_hash)
            if event is None or event.get("kind") != "preflight":
                return "preflight hash does not identify a ledger preflight event"
            payload = event["payload"]
            if payload.get("action") != action:
                return "typed action differs from the ledger-bound preflight action"
            if payload.get("rollback_plan") != (result.get("rollback_plan") or {}):
                return "rollback plan differs from the ledger-bound preflight plan"
            ledger_decision = payload.get("decision")
            if result.get("decision") != ledger_decision:
                return "result decision differs from the ledger-bound preflight decision"
            if ledger_decision not in ("ALLOW", "WARN", "REQUIRE_CONFIRMATION"):
                return f"ledger-bound decision {ledger_decision!r} is not executable"
            if ledger_decision == "REQUIRE_CONFIRMATION":
                approved = False
                for row in ledger.con.execute(
                    "SELECT payload FROM events WHERE kind='override' ORDER BY id"
                ):
                    try:
                        override = json.loads(row["payload"])
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if (
                        override.get("preflight_hash") == preflight_hash
                        and override.get("by") == "human"
                    ):
                        approved = True
                        break
                if not approved:
                    return "confirmation-required preflight has no human override receipt"
    except Exception as exc:
        return f"preflight ledger validation failed: {type(exc).__name__}: {exc}"
    return ""


def _execute_approved(cmd: str, mode: str, result, argv=None) -> int:
    if argv is None:
        argv = shlex.split(cmd, posix=os.name != "nt")
        if os.name == "nt":
            argv = [part[1:-1] if len(part) >= 2 and part[0] == part[-1] == '"' else part for part in argv]
    binding_error = _execution_binding_error(cmd, mode, result, argv)
    if binding_error:
        print(f"\n[HELD] {binding_error}; command was not executed.")
        return 1
    try:
        rollback_ok = _materialize_rollback(result)
    except Exception as exc:
        plan = result.get("rollback_plan") or {}
        plan.update({
            "snapshot_status": "failed",
            "restorable": False,
            "snapshot_errors": [{
                "error_type": type(exc).__name__,
                "error": str(exc),
            }],
        })
        rollback_ok = False
    rollback_receipt = _rollback_receipt(result)
    if not rollback_ok:
        try:
            _append_execution(
                "execution_failed",
                result,
                rollback_receipt,
                executed=False,
                execution_attempted=False,
                exit_code=None,
                error_type="RollbackMaterializationError",
                error="required rollback materialization failed",
            )
        except Exception as exc:
            print(
                f"\n[HELD] rollback failed before execution and its failure receipt "
                f"could not be recorded: {type(exc).__name__}: {exc}"
            )
        return 1
    try:
        started_hash = _append_execution(
            "execution_started",
            result,
            rollback_receipt,
            executed=False,
            execution_attempted=True,
            mode=mode,
        )
    except Exception as exc:
        print(f"\n[HELD] execution receipt could not be recorded: {type(exc).__name__}: {exc}")
        return 1
    try:
        if mode == "shell":
            exit_code = subprocess.call(cmd, shell=True)
        else:
            exit_code = subprocess.call(list(argv))
    except Exception as exc:
        try:
            _append_execution(
                "execution_failed",
                result,
                rollback_receipt,
                executed=False,
                execution_attempted=True,
                execution_started_hash=started_hash,
                exit_code=None,
                error_type=type(exc).__name__,
                error=str(exc),
            )
        except Exception as receipt_exc:
            return _handle_terminal_receipt_failure(
                result,
                rollback_receipt,
                started_hash,
                "execution_failed",
                None,
                receipt_exc,
                execution_error=f"{type(exc).__name__}: {exc}",
            )
        return 1
    terminal_kind = "execution_completed" if exit_code == 0 else "execution_failed"
    try:
        _append_execution(
            terminal_kind,
            result,
            rollback_receipt,
            executed=True,
            execution_attempted=True,
            execution_started_hash=started_hash,
            exit_code=exit_code,
            **({} if exit_code == 0 else {
                "error_type": "NonZeroExit",
                "error": f"process exited with status {exit_code}",
            }),
        )
    except Exception as receipt_exc:
        return _handle_terminal_receipt_failure(
            result,
            rollback_receipt,
            started_hash,
            terminal_kind,
            exit_code,
            receipt_exc,
        )
    return exit_code

def main(argv=None):
    ap = argparse.ArgumentParser(prog="continuity", description="AI Agent Governance Gateway")
    ap.add_argument("--db", default=None, help="Continuity memory DB (overrides CONTINUITYOS_DB)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    pf = sub.add_parser("preflight"); pf.add_argument("tool"); pf.add_argument("command"); pf.add_argument("--cwd", default=None); pf.add_argument("--json", action="store_true")
    rn = sub.add_parser("run"); rn.add_argument("tool"); rn.add_argument("rest", nargs=argparse.REMAINDER)
    au = sub.add_parser("audit"); au.add_argument("-n", type=int, default=20)
    rb = sub.add_parser("rollback"); rb.add_argument("snapshot_id")
    a = ap.parse_args(argv)

    if a.cmd == "init":
        os.makedirs(HOME, exist_ok=True)
        with Ledger(LEDGER):
            pass
        try:
            policy_path = discover_policy(HOME)
        except PolicyError as exc:
            print(f"policy error: {exc}")
            return 1
        if not policy_path:
            with open(POLICY_JSON, "w", encoding="utf-8", newline="\n") as f:
                json.dump(default_policy(), f, ensure_ascii=False, indent=2, sort_keys=True)
                f.write("\n")
            policy_path = POLICY_JSON
        try:
            load_policy(policy_path)
        except PolicyError as exc:
            print(f"policy error: {exc}")
            return 1
        print(f"initialized: {LEDGER}\npolicy: {policy_path} (edit to customize)")
        return 0

    if a.cmd == "preflight":
        r, _ = _decide(
            a.command,
            tool=a.tool,
            agent="cli-preflight",
            cwd=a.cwd,
            db=a.db,
        )
        if a.json:
            print(json.dumps(r, ensure_ascii=False, sort_keys=True))
        else:
            _print(r)
        return 0

    if a.cmd == "rollback":
        from .rollback import restore
        r = restore(a.snapshot_id); print(r); return 0 if r.get("ok") else 1

    if a.cmd == "audit":
        with Ledger(LEDGER) as led:
            for e in reversed(led.export(a.n)):
                p = e["payload"]
                action = p.get("action") or {}
                print(f"  {e['hash'][:12]} [{p.get('decision','?'):20}] {action.get('command', p.get('command',''))[:50]}")
            v = led.verify()
        print(("\n[OK] ledger intact, %d events" % v["verified"]) if v["ok"] else ("\n[TAMPERED] at #%s" % v.get("broken_at")))
        return 0

    if a.cmd == "run":
        rest = list(a.rest)
        if rest and rest[0] == "--": rest = rest[1:]
        # Shorthand `continuity run <cmd...>`: the `tool` positional actually holds the
        # first command token (e.g. `run npm test` -> tool="npm", rest=["test"]).
        # Prepend it back so the first token isn't lost (PR-7 fix, GPT audit 2026-07-04).
        if a.tool not in ("exec", "shell"):
            rest = [a.tool] + rest
        if not rest:
            print("usage: continuity run [exec|shell] -- <command>"); return 2
        # exec = argv-only (safe): reject shell operators instead of silently mis-running.
        # shell = real shell semantics (&&, |, >, $()) but classified more strictly.
        mode = a.tool if a.tool in ("exec", "shell") else "exec"
        exec_argv = list(rest)
        cmd = " ".join(rest) if mode == "shell" else (
            subprocess.list2cmdline(exec_argv) if os.name == "nt" else shlex.join(exec_argv)
        )
        _SHELL_OPS = re.compile(r"&&|\|\||[|<>]|\$\(|`|;")
        if mode == "exec" and len(exec_argv) == 1 and _SHELL_OPS.search(exec_argv[0]):
            print("\n[BLOCKED] exec mode is argv-only and does not run shell operators (&&, |, >, $(), ;).")
            print("   Use:  continuity run shell -- \"" + cmd + "\"   (mediated shell mode)"); return 2
        r, spec = _decide(
            cmd,
            tool=("shell" if mode == "shell" else "exec"),
            agent="cli-run",
            args=exec_argv,
            db=a.db,
        )
        d = r["decision"]
        if d == "DRY_RUN_ONLY":
            exit_code = EXIT_DRY_RUN_ONLY
            print(json.dumps({
                "decision": d,
                "executed": False,
                "execution_attempted": False,
                "exit_code": exit_code,
                "preflight_hash": r.get("ledger_hash"),
                "action": r.get("action"),
                "reasons": r.get("reasons") or [],
                "rollback_receipt": _rollback_receipt(r),
            }, ensure_ascii=False, sort_keys=True))
            return exit_code
        _print(r)
        if d == "ALLOW":
            return _execute_approved(cmd, mode, r, argv=exec_argv)
        if d in ("DENY", "HOLD"):
            print(f"\n[BLOCKED] ({d}). Command was NOT executed.")
            return 1
        if d == "WARN":
            print("\n[WARN] proceeding (logged). Review the reasons above.")
            # Preserve shell semantics on WARN too — mirror the ALLOW branch, don't
            # silently downgrade `shell` mode to argv (PR-7 fix, GPT audit 2026-07-04).
            return _execute_approved(cmd, mode, r, argv=exec_argv)
        if d == "REQUIRE_CONFIRMATION":
            if not sys.stdin.isatty():
                print("\n[HELD] REQUIRE_CONFIRMATION in non-interactive mode. NOT executed."); return 1
            ans = input("\nRequires confirmation. Execute anyway? [y/N] ").strip().lower()
            if ans == "y":
                with Ledger(LEDGER) as led:
                    led.append("override", {"command": cmd, "by": "human", "preflight_hash": r.get("ledger_hash")})
                return _execute_approved(cmd, mode, r, argv=exec_argv)
            print("aborted by user."); return 1
    return 0

def _print(r):
    print(f"decision: {r['decision']}" + (f"  (severity: {r['severity']})" if r.get('severity') else ""))
    for rs in r["reasons"]: print("  -", rs)
    if r.get("ledger_hash"): print("  ledger:", r["ledger_hash"][:12])

if __name__ == "__main__":
    sys.exit(main())
