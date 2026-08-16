import pytest
from sct.stats.cluster import inferential_gate, paired_cluster_randomization


def test_inferential_gate_requires_n_and_independent_clusters():
    assert inferential_gate(n_cases=99,n_clusters=10)["allowed"] is False
    assert inferential_gate(n_cases=100,n_clusters=5)["allowed"] is False
    assert inferential_gate(n_cases=100,n_clusters=6)["allowed"] is True


def test_exact_cluster_randomization_known_answer():
    rows=[{"cluster_key":"a","delta":1.0},{"cluster_key":"b","delta":1.0}]
    out=paired_cluster_randomization(rows)
    assert out["method"]=="exact_sign_flip"
    assert out["n_clusters"]==2
    # Four sign assignments; two have |mean| >= observed |1|.
    assert out["p_value"]==pytest.approx(.5)
