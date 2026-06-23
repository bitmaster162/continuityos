"""Pluggable embeddings.

Default `HashingEmbedder` is dependency-free and deterministic: char n-gram
hashing into a fixed-dim L2-normalized vector. Good enough for local semantic
recall and fully offline. For production-grade semantics, pass any callable
that maps str->list[float] (e.g. a sentence-transformers model) as `embedder`.
"""
from __future__ import annotations
import math, re, hashlib
from typing import List

_TOKEN = re.compile(r"[\w]+", re.UNICODE)

def _stable_hash(s: str) -> int:
    # deterministic across processes/runs (unlike builtin hash() for str)
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "big")

def _ngrams(text: str, n: int = 3):
    toks = _TOKEN.findall((text or "").lower())
    for t in toks:                       # word-level tokens
        yield t
    joined = " ".join(toks)
    for i in range(len(joined) - n + 1):  # char n-grams (morphology / typos / multilingual)
        yield joined[i:i+n]

class HashingEmbedder:
    """Deterministic offline embedder. dim defaults to 256."""
    def __init__(self, dim: int = 256):
        self.dim = dim

    def __call__(self, text: str) -> List[float]:
        vec = [0.0] * self.dim
        for g in _ngrams(text):
            h = _stable_hash(g)
            idx = h % self.dim
            sign = 1.0 if (h >> 16) & 1 else -1.0
            vec[idx] += sign
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

def cosine(a: List[float], b: List[float]) -> float:
    # vectors are L2-normalized -> dot product == cosine
    return sum(x * y for x, y in zip(a, b))
