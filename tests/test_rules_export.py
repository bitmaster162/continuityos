"""Offline tests for the canon translator (cos rules)."""
import os, tempfile
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
from continuityos.memory import Memory
from continuityos.continuity import Continuity
from continuityos.rules_export import export_rules, TARGET_PATHS

def _seed():
    d = tempfile.mkdtemp()
    m = Memory(os.path.join(d, "m.db"))
    c = Continuity(memory=m)
    c.add_canon("Agents propose typed intent; deterministic systems dispose.")
    c.add_canon("LLM never controls capital directly.")
    m.remember("Prefer Apache-2.0 for OSS.", namespace="rules")
    c.set_frontier("trunk", "ContinuityOS OSS launch")
    return m

def test_dry_run_renders_all_targets():
    m = _seed()
    res = export_rules(m, targets=("claude", "agents", "cursor"), dry_run=True)
    assert res["canon"] == 2 and res["rules"] == 1 and res["frontiers"] >= 1, res
    assert set(res["contents"]) == {"claude", "agents", "cursor"}
    assert "propose typed intent" in res["contents"]["claude"]
    assert res["written"] == []
    print("PASS dry_run_renders_all_targets")

def test_writes_files_and_cursor_frontmatter():
    m = _seed(); out = tempfile.mkdtemp()
    res = export_rules(m, out_dir=out, targets=("claude", "agents", "cursor"))
    for t, rel in TARGET_PATHS.items():
        p = os.path.join(out, rel)
        assert os.path.exists(p), p
        assert "propose typed intent" in open(p, encoding="utf-8").read()
    mdc = open(os.path.join(out, TARGET_PATHS["cursor"]), encoding="utf-8").read()
    assert mdc.startswith("---") and "alwaysApply: true" in mdc, mdc[:120]
    assert "Current focus" in open(os.path.join(out, "CLAUDE.md"), encoding="utf-8").read()
    print("PASS writes_files_and_cursor_frontmatter")

def test_single_target_only():
    m = _seed(); out = tempfile.mkdtemp()
    res = export_rules(m, out_dir=out, targets=("claude",))
    assert os.path.exists(os.path.join(out, "CLAUDE.md"))
    assert not os.path.exists(os.path.join(out, "AGENTS.md"))
    assert len(res["written"]) == 1
    print("PASS single_target_only")

def test_empty_canon_no_crash():
    d = tempfile.mkdtemp(); m = Memory(os.path.join(d, "m.db"))
    res = export_rules(m, targets=("claude",), dry_run=True)
    assert "(none yet)" in res["contents"]["claude"]
    print("PASS empty_canon_no_crash")

def run():
    for n in sorted(k for k in globals() if k.startswith("test_")):
        globals()[n]()
    print("ALL_RULES_TESTS_PASS")

if __name__ == "__main__":
    run()
