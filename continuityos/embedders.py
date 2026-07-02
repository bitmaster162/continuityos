"""Optional production-grade embedders (pluggable into Memory(embedder=...)).

Default stays the dependency-free offline HashingEmbedder. These give real
semantic recall:

  pip install "continuityos[fast]"   # fastembed: ONNX, no torch, small + fast
  pip install "continuityos[st]"     # sentence-transformers: widest model choice

  from continuityos import Memory
  from continuityos.embedders import FastEmbedEmbedder
  m = Memory("memory.db", embedder=FastEmbedEmbedder())

All embedders return L2-normalized vectors so cosine == dot product.
"""
from __future__ import annotations
import math
from typing import List

def _l2(v: List[float]) -> List[float]:
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]

class FastEmbedEmbedder:
    """ONNX embedder via `fastembed` (no torch). Default model bge-small-en-v1.5 (384-dim)."""
    def __init__(self, model: str = "BAAI/bge-small-en-v1.5"):
        try:
            from fastembed import TextEmbedding
        except Exception as e:
            raise ImportError('FastEmbedEmbedder needs:  pip install "continuityos[fast]"') from e
        self._model = TextEmbedding(model_name=model)

    def __call__(self, text: str) -> List[float]:
        vec = list(next(iter(self._model.embed([text or ""]))))
        return _l2([float(x) for x in vec])

class Model2VecEmbedder:
    """Static embeddings via `model2vec` (30MB, no torch/onnx — lightest real embedder).
    Default potion-base-8M (256-dim). pip install "continuityos[m2v]"."""
    def __init__(self, model: str = "minishlab/potion-base-8M"):
        try:
            from model2vec import StaticModel
        except Exception as e:
            raise ImportError('Model2VecEmbedder needs:  pip install "continuityos[m2v]"') from e
        self._model = StaticModel.from_pretrained(model)

    def __call__(self, text: str) -> List[float]:
        return _l2([float(x) for x in self._model.encode([text or ""])[0]])

class SentenceTransformerEmbedder:
    """sentence-transformers embedder. Default all-MiniLM-L6-v2 (384-dim)."""
    def __init__(self, model: str = "all-MiniLM-L6-v2"):
        try:
            from sentence_transformers import SentenceTransformer
        except Exception as e:
            raise ImportError('SentenceTransformerEmbedder needs:  pip install "continuityos[st]"') from e
        self._model = SentenceTransformer(model)

    def __call__(self, text: str) -> List[float]:
        v = self._model.encode(text or "", normalize_embeddings=True)
        return [float(x) for x in v]
