import os, tempfile
from continuityos.gate import ActionSpec, preflight, Ledger, DEFAULT_POLICY

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

def test_real_rollback_restores_file():
    from continuityos.gate import ActionSpec, preflight
    from continuityos.gate.rollback import restore
    import tempfile, os
    f = os.path.join(tempfile.mkdtemp(), "d.db"); open(f, "w").write("ORIG")
    r = preflight(ActionSpec(tool="shell", command="rm " + f, paths=[f]))
    sid = r["rollback_plan"]["snapshot_id"]
    open(f, "w").write("GONE")
    assert restore(sid)["restored"] == 1
    assert open(f).read() == "ORIG"
