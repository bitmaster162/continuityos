import tempfile, os
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
from continuityos.memory import Memory
from continuityos.epochgraph import EpochGraph

def _g():
    return EpochGraph(Memory(os.path.join(tempfile.mkdtemp(), "e.db")))

def test_commit_and_log_order():
    g = _g(); g.commit("main", "a", {"wr": 0.3}); g.commit("main", "b", {"wr": 0.4})
    log = g.log("main")
    assert [c["epoch"] for c in log] == [2, 1]        # newest first, like git log
    assert log[0]["metrics"]["wr"] == 0.4

def test_branch_forks_from_head():
    g = _g(); g.commit("main", "a"); g.commit("main", "b")
    head = g.head("main"); g.branch("exp", from_branch="main"); fc = g.commit("exp", "c")
    G = g.to_graph()
    src = [e["source"] for e in G["edges"] if e["target"] == fc][0]
    assert src == head                                 # fork parent = source branch HEAD

def test_graph_export_is_dag():
    g = _g(); g.commit("main", "a"); g.commit("main", "b")
    G = g.to_graph()
    assert len(G["nodes"]) == 2 and len(G["edges"]) == 1 and "main" in G["branches"]
