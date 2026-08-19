"""Vector search backends with graceful degradation.

- hnswlib (optional, true ANN, millions of vectors) if installed
- numpy (vectorized cosine, fast to ~100k) if installed
- pure-python brute force (always works, zero deps)

The store keeps vectors; this module just ranks them against a query. Memory
picks the best available backend automatically.
"""
from __future__ import annotations
from typing import List, Tuple
try:
    import numpy as _np
except Exception:
    _np = None


def _validate_dimensions(query_vec: List[float], rows: List[dict]) -> int:
    """Require one exact vector dimension across query and every candidate.

    Silent truncation is forbidden. In particular, Python's ``zip`` would
    otherwise score a 768-D query against 256/384-D legacy vectors using only
    the shared prefix, which produces a plausible-looking but invalid score.
    """
    qdim = len(query_vec)
    if qdim <= 0:
        raise ValueError("query vector must be non-empty")
    dims = sorted({len(r.get("vec") or []) for r in rows})
    if not dims or dims == [0]:
        raise ValueError("candidate vectors must be non-empty")
    if len(dims) != 1 or dims[0] != qdim:
        raise ValueError(
            f"vector dimension mismatch: query={qdim}, candidates={dims}; "
            "re-embed memory into one compatible vector space before semantic ranking"
        )
    return qdim


def rank(query_vec: List[float], rows: List[dict], top: int = 50) -> List[Tuple[float, dict]]:
    """rows: [{'vec': [..], ...}] -> [(cosine, row)] sorted desc, top-k. Vectors are L2-normalized."""
    if not rows:
        return []
    _validate_dimensions(query_vec, rows)
    if _np is not None:
        q = _np.asarray(query_vec, dtype=_np.float32)
        M = _np.asarray([r["vec"] for r in rows], dtype=_np.float32)   # (n, d)
        sims = M @ q                                                   # cosine (normalized)
        if top < len(rows):
            idx = _np.argpartition(-sims, top)[:top]
            idx = idx[_np.argsort(-sims[idx])]
        else:
            idx = _np.argsort(-sims)
        return [(float(sims[i]), rows[i]) for i in idx]
    # pure python fallback
    out = []
    for r in rows:
        v = r["vec"]
        out.append((sum(a*b for a, b in zip(query_vec, v)), r))
    out.sort(key=lambda x: x[0], reverse=True)
    return out[:top]
