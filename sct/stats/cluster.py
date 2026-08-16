from __future__ import annotations

from collections import defaultdict
from itertools import product
from typing import Iterable, Mapping, Any
import random


def inferential_gate(*, n_cases: int, n_clusters: int) -> dict[str,Any]:
    failures=[]
    if n_cases<100: failures.append("n<100")
    if n_clusters<6: failures.append("K<6")
    return {"allowed":not failures,"n_cases":n_cases,"n_clusters":n_clusters,"failures":failures}


def paired_cluster_randomization(rows: Iterable[Mapping[str,Any]], *, metric: str="delta", seed: int=20260817,
                                 monte_carlo: int=100000) -> dict[str,Any]:
    by=defaultdict(list)
    n=0
    for row in rows:
        by[str(row["cluster_key"])].append(float(row[metric])); n+=1
    if not by: raise ValueError("at least one cluster required")
    cluster_means={k:sum(v)/len(v) for k,v in by.items()}
    vals=list(cluster_means.values()); k=len(vals)
    observed=sum(vals)/k
    target=abs(observed)
    if k<=20:
        total=extreme=0
        for signs in product((-1.0,1.0), repeat=k):
            stat=abs(sum(s*v for s,v in zip(signs,vals))/k)
            total+=1
            if stat+1e-15>=target: extreme+=1
        p=extreme/total; method="exact_sign_flip"
    else:
        rng=random.Random(seed); extreme=0
        for _ in range(monte_carlo):
            stat=abs(sum((1 if rng.random()<0.5 else -1)*v for v in vals)/k)
            extreme += stat+1e-15>=target
        p=(extreme+1)/(monte_carlo+1); method="monte_carlo_sign_flip"
    return {"n_cases":n,"n_clusters":k,"observed_cluster_mean_delta":observed,"p_value":p,"method":method,"seed":seed}
