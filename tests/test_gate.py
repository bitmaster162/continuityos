import os, tempfile
from continuityos.gate import ActionSpec, preflight, Ledger, DEFAULT_POLICY


def _mock_preflight_receipt(ledger_path, cmd, tool, args, decision):
    action = {
        "tool": tool,
        "command": cmd,
        "args": list(args),
        "paths": [],
        "cwd": os.getcwd(),
        "agent": "cli-run",
        "meta": {},
    }
    rollback_plan = {}
    with Ledger(ledger_path) as ledger:
        receipt_hash = ledger.append("preflight", {
            "action": action,
            "decision": decision,
            "rollback_plan": rollback_plan,
        })
    return {
        "decision": decision,
        "reasons": [],
        "ledger_hash": receipt_hash,
        "action": action,
        "rollback_plan": rollback_plan,
    }, None

def test_rm_rf_denied():
    r = preflight(ActionSpec(tool="shell", command="rm -rf /", paths=["/"]))
    assert r["decision"] == "DENY"

def test_safe_command_allowed():
    # truly safe single command (argv, no shell operators) stays ALLOW
    r = preflight(ActionSpec(tool="shell", command="ls -la"))
    assert r["decision"] == "ALLOW"

def test_shell_chain_warns():
    # PR-3: shell chaining (&&) is no longer silently ALLOWed — it warns
    r = preflight(ActionSpec(tool="shell", command="ls -la && npm test"))
    assert r["decision"] in ("WARN", "REQUIRE_CONFIRMATION", "HOLD")

def test_force_push_requires_confirmation():
    r = preflight(ActionSpec(tool="shell", command="git push origin main --force"))
    assert r["decision"] == "REQUIRE_CONFIRMATION"

def test_secret_read_flagged():
    r = preflight(ActionSpec(tool="shell", command="cat .env", paths=[".env"]))
    assert r["decision"] in ("REQUIRE_CONFIRMATION", "DENY")

def test_ledger_hash_chain_verifies():
    p = os.path.join(tempfile.mkdtemp(), "l.db"); L = Ledger(p)
    for c in ["rm -rf /", "ls", "git push -f"]:
        preflight(ActionSpec(tool="shell", command=c), ledger=L)
    assert L.verify()["ok"] is True

def test_ledger_tamper_detected():
    p = os.path.join(tempfile.mkdtemp(), "l.db"); L = Ledger(p)
    preflight(ActionSpec(tool="shell", command="rm -rf /"), ledger=L)
    L.con.execute("UPDATE events SET payload='{\"x\":1}' WHERE id=1"); L.con.commit()
    assert L.verify()["ok"] is False

def test_interpreter_delete_blocked():
    from continuityos.gate import ActionSpec, preflight
    for c in ['python -c "import shutil;shutil.rmtree(\'/\')"', 'find / -delete', 'node -e "require(\'fs\').rmSync(\'/\')"']:
        assert preflight(ActionSpec(tool="shell", command=c))["decision"] == "DENY"

def test_canon_context_escalates():
    from continuityos import Continuity
    from continuityos.gate import ActionSpec, preflight
    import tempfile, os
    c = Continuity(db=os.path.join(tempfile.mkdtemp(), "c.db"))
    c.add_canon("Never modify the production database directly.")
    r = preflight(ActionSpec(tool="shell", command="update production database now"), context=c)
    assert r["decision"] in ("REQUIRE_CONFIRMATION", "DENY")
    assert any("canon" in x for x in r["reasons"])

def test_real_rollback_restores_file(tmp_path, monkeypatch):
    import continuityos.gate.rollback as rollback
    monkeypatch.setattr(rollback, "SNAP_ROOT", str(tmp_path / "snapshots"))
    f = tmp_path / "d.db"
    f.write_text("ORIG", encoding="utf-8")
    snap = rollback.snapshot([str(f)])
    assert snap["restorable"] is True
    f.write_text("GONE", encoding="utf-8")
    assert rollback.restore(snap["id"])["restored"] == 1
    assert f.read_text(encoding="utf-8") == "ORIG"


def test_exec_mode_rejects_shell_operators():
    # PR-3.5: exec is argv-only; shell operators are a hard reject with guidance
    import subprocess, sys
    r = subprocess.run([sys.executable, "-m", "continuityos.gate.cli", "run", "exec", "--", "ls && rm -rf x"],
                       capture_output=True, text=True)
    assert r.returncode == 2
    assert "argv-only" in r.stdout or "shell operators" in r.stdout


def test_run_shorthand_preserves_first_token(tmp_path, monkeypatch):
    # PR-7: `continuity run npm test` must NOT drop the first token ("npm").
    import continuityos.gate.cli as gc
    cap = {}
    monkeypatch.setattr(gc, "LEDGER", str(tmp_path / "ledger.db"))
    monkeypatch.setattr(
        gc,
        "_decide",
        lambda cmd, tool="shell", agent="cli-run", **kwargs:
            _mock_preflight_receipt(
                gc.LEDGER, cmd, tool, kwargs["args"], "ALLOW"
            ),
    )
    monkeypatch.setattr(gc.subprocess, "call", lambda *a, **k: cap.update(args=a, kwargs=k) or 0)
    gc.main(["run", "npm", "test"])
    # shorthand -> exec mode -> argv via shlex.split; first token preserved
    assert cap["args"][0] == ["npm", "test"], f"first token lost: {cap['args'][0]!r}"


def test_shell_warn_executes_with_shell_true(tmp_path, monkeypatch):
    # PR-7: a WARN decision in shell mode must keep shell semantics (shell=True),
    # not silently degrade to argv.
    import continuityos.gate.cli as gc
    cap = {}
    monkeypatch.setattr(gc, "LEDGER", str(tmp_path / "ledger.db"))
    monkeypatch.setattr(
        gc,
        "_decide",
        lambda cmd, tool="shell", agent="cli-run", **kwargs:
            _mock_preflight_receipt(
                gc.LEDGER, cmd, tool, kwargs["args"], "WARN"
            ),
    )
    monkeypatch.setattr(gc.subprocess, "call", lambda *a, **k: cap.update(args=a, kwargs=k) or 0)
    gc.main(["run", "shell", "--", "echo ok && echo done"])
    assert cap["kwargs"].get("shell") is True, "WARN shell mode lost shell=True"
    assert cap["args"][0] == "echo ok && echo done"


def test_exec_uses_exact_argv_that_was_preflighted(tmp_path, monkeypatch):
    import continuityos.gate.cli as gc
    captured = {}

    def decide(cmd, tool="shell", agent="cli-run", **kwargs):
        captured["checked_args"] = kwargs["args"]
        return _mock_preflight_receipt(
            gc.LEDGER, cmd, tool, kwargs["args"], "ALLOW"
        )

    monkeypatch.setattr(gc, "LEDGER", str(tmp_path / "ledger.db"))
    monkeypatch.setattr(gc, "_decide", decide)
    monkeypatch.setattr(gc.subprocess, "call", lambda argv, **kwargs: captured.update(
        {"executed_args": argv, "exec_kwargs": kwargs}
    ) or 0)
    argv = ["python", "-c", "print('hello world')"]
    assert gc.main(["run", "exec", "--", *argv]) == 0
    assert captured["checked_args"] == argv
    assert captured["executed_args"] == argv
