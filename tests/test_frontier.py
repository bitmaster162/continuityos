import tempfile, os
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
from continuityos.memory import Memory
from continuityos.frontier import FrontierDesk

def _d():
    return FrontierDesk(Memory(os.path.join(tempfile.mkdtemp(), "f.db")))

def test_home_domain_high_asymmetry_is_edge():
    d = _d(); d.signal("ai-agents", "src", "big edge", 0.85, 3, "now")
    assert d.digest()["by_decision"]["EDGE"]

def test_low_asymmetry_is_avoid():
    d = _d(); d.signal("robotics", "hype", "noise", 0.2, 3, "now")
    assert d.digest()["by_decision"]["AVOID"]

def test_far_domain_high_asym_tests_or_learns():
    d = _d(); d.signal("quantum-sec", "src", "pqc", 0.75, 2, "soon")
    dg = d.digest()
    assert dg["by_decision"]["TEST"] or dg["by_decision"]["LEARN"]
    assert dg["total"] == 1
