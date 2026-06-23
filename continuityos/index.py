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

def best_backend() -> str:
    try:
        import hnswlib  # noqa
        return "hnswlib"
    except Exception:
        return "numpy" if _np is not None else "python"

def rank(query_vec: List[float], rows: List[dict], top: int = 50) -> List[Tuple[float, dict]]:
    """rows: [{'vec': [..], ...}] -> [(cosine, row)] sorted desc, top-k. Vectors are L2-normalized."""
    if not rows:
        return []
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
