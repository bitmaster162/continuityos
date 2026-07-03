import os, tempfile
from continuityos import Memory
from continuityos.orchestrator import Orchestrator, Step

def _m():
    return Memory(os.path.join(tempfile.mkdtemp(), "o.db"))

def test_dag_order_and_context_flow():
    calls = []
    agents = {"a": lambda p: (calls.append("a"), "digest: BTC flat")[1],
              "b": lambda p: (calls.append("b"), "report built from: " + ("digest" if "digest" in p else "?"))[1]}
    orc = Orchestrator(_m(), agents)
    r = orc.run([Step("s2", "synthesize", depends_on=["s1"], assignee="b"),
                 Step("s1", "collect", assignee="a")])
    assert r["ok"] and calls == ["a", "b"]
    assert "digest" in r["steps"]["s2"]["result"]  # upstream flowed downstream

def test_failure_blocks_dependents_and_antiloop():
    def flaky(p): raise RuntimeError("boom")
    orc = Orchestrator(_m(), {"f": flaky, "ok": lambda p: "fine"})
    r = orc.run([Step("s1", "will fail", assignee="f"),
                 Step("s2", "depends", depends_on=["s1"], assignee="ok")])
    assert r["steps"]["s1"]["status"] == "failed" and r["steps"]["s1"]["attempts"] == 3
    assert r["steps"]["s2"]["status"] == "blocked" and not r["ok"]

def test_gate_blocks():
    orc = Orchestrator(_m(), {"a": lambda p: "x"}, gate=lambda s: "деплой" not in s.goal)
    r = orc.run([Step("s1", "деплой в прод", assignee="a")])
    assert r["steps"]["s1"]["status"] == "blocked"
