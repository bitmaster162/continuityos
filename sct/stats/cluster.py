from __future__ import annotations

from collections import defaultdict
from itertools import product
from typing import Iterable, Mapping, Any
import math
import random


def inferential_gate(*, n_cases: int, n_clusters: int) -> dict[str, Any]:
    failures = []
    if n_cases < 100:
        failures.append("n<100")
    if n_clusters < 6:
        failures.append("K<6")
    return {
        "allowed": not failures,
        "n_cases": n_cases,
        "n_clusters": n_clusters,
        "failures": failures,
        "semantics": "MINIMUM_INFERENCE_ADMISSION_FLOOR_NOT_POWER_OR_INDEPENDENCE_PROOF",
    }


def _cluster_means(rows: Iterable[Mapping[str, Any]], metric: str) -> tuple[int, dict[str, float]]:
    grouped = defaultdict(list)
    n = 0
    for row in rows:
        key = str(row["cluster_key"])
        if not key:
            raise ValueError("cluster_key must be non-empty")
        value = float(row[metric])
        if not math.isfinite(value):
            raise ValueError("metric must be finite")
        grouped[key].append(value)
        n += 1
    if not grouped:
        raise ValueError("at least one cluster required")
    return n, {key: sum(values) / len(values) for key, values in grouped.items()}


def paired_cluster_randomization(
    rows: Iterable[Mapping[str, Any]],
    *,
    metric: str = "delta",
    seed: int = 20260817,
    monte_carlo: int = 100000,
) -> dict[str, Any]:
    """Cluster sign-flip sensitivity calculation.

    The legacy function name is retained for API compatibility. SCT observes both
    B and C on every enrolled case; there is no randomized treatment assignment.
    Therefore this is not design-based randomization inference. Its p-value is
    interpretable only under the preregistered null invariance assumption that
    cluster-mean paired deltas are exchangeable under sign reversal.
    """
    n, cluster_means = _cluster_means(rows, metric)
    vals = list(cluster_means.values())
    k = len(vals)
    observed = sum(vals) / k
    target = abs(observed)
    if k <= 20:
        total = extreme = 0
        for signs in product((-1.0, 1.0), repeat=k):
            stat = abs(sum(s * value for s, value in zip(signs, vals)) / k)
            total += 1
            if stat + 1e-15 >= target:
                extreme += 1
        p_value = extreme / total
        method = "exact_cluster_sign_flip"
    else:
        if monte_carlo < 1:
            raise ValueError("monte_carlo must be positive")
        rng = random.Random(seed)
        extreme = 0
        for _ in range(monte_carlo):
            stat = abs(sum((1 if rng.random() < 0.5 else -1) * value for value in vals) / k)
            extreme += stat + 1e-15 >= target
        p_value = (extreme + 1) / (monte_carlo + 1)
        method = "monte_carlo_cluster_sign_flip"
    return {
        "n_cases": n,
        "n_clusters": k,
        "observed_cluster_mean_delta": observed,
        "p_value": p_value,
        "method": method,
        "seed": seed,
        "design_based_randomization": False,
        "null_invariance_assumption": "CLUSTER_MEAN_PAIRED_DELTAS_EXCHANGEABLE_UNDER_SIGN_REVERSAL",
        "interpretation": "SIGN_FLIP_SENSITIVITY_UNDER_SYMMETRY_NOT_RANDOM_ASSIGNMENT_INFERENCE",
    }


def cluster_bootstrap_ci(
    rows: Iterable[Mapping[str, Any]],
    *,
    metric: str = "delta",
    seed: int = 20260817,
    samples: int = 10000,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """Percentile cluster bootstrap over cluster-mean paired deltas.

    This is fixed-analysis and descriptive/uncertainty output; it does not
    override the n>=100/K>=6 claim gate.
    """
    n, cluster_means = _cluster_means(rows, metric)
    vals = list(cluster_means.values())
    k = len(vals)
    if samples < 100:
        raise ValueError("samples must be >= 100")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0,1)")
    rng = random.Random(seed)
    boot = []
    for _ in range(samples):
        draw = [vals[rng.randrange(k)] for _ in range(k)]
        boot.append(sum(draw) / k)
    boot.sort()

    def percentile(q: float) -> float:
        pos = q * (len(boot) - 1)
        lo = int(math.floor(pos))
        hi = int(math.ceil(pos))
        if lo == hi:
            return boot[lo]
        frac = pos - lo
        return boot[lo] * (1.0 - frac) + boot[hi] * frac

    return {
        "n_cases": n,
        "n_clusters": k,
        "observed_cluster_mean_delta": sum(vals) / k,
        "lower": percentile(alpha / 2.0),
        "upper": percentile(1.0 - alpha / 2.0),
        "confidence": 1.0 - alpha,
        "method": "percentile_cluster_bootstrap",
        "samples": samples,
        "seed": seed,
    }
