
import pytest
from sct.stats.cluster import inferential_gate, paired_cluster_randomization, cluster_bootstrap_ci


def test_inferential_gate_requires_n_and_independent_clusters():
    assert inferential_gate(n_cases=99, n_clusters=10)["allowed"] is False
    assert inferential_gate(n_cases=100, n_clusters=5)["allowed"] is False
    assert inferential_gate(n_cases=100, n_clusters=6)["allowed"] is True


def test_exact_cluster_randomization_known_answer():
    rows = [{"cluster_key": "a", "delta": 1.0}, {"cluster_key": "b", "delta": 1.0}]
    out = paired_cluster_randomization(rows)
    assert out["method"] == "exact_cluster_sign_flip"
    assert out["n_clusters"] == 2
    assert out["p_value"] == pytest.approx(.5)


def test_cluster_bootstrap_known_answer_constant_clusters():
    rows = [{"cluster_key": f"c{i}", "delta": 0.25} for i in range(6)]
    out = cluster_bootstrap_ci(rows, samples=500)
    assert out["lower"] == pytest.approx(0.25)
    assert out["upper"] == pytest.approx(0.25)
    assert out["observed_cluster_mean_delta"] == pytest.approx(0.25)
