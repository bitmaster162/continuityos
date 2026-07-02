# ContinuityOS — Recall Benchmarks

Honest, reproducible numbers. Run yourself: `python bench/recall_bench.py`.

## Setup
- 10 labeled (memory → paraphrased query) pairs (`bench/recall_bench.py`, synthetic).
- Hybrid recall: `0.6·semantic + 0.4·keyword`. Metric: recall@k and MRR.
- Hardware: CPU only. Swap `load_dataset()` for **LoCoMo / LongMemEval** for comparable public numbers.

## Results (2026-06-24, post-audit)

| Embedder | recall@1 | recall@3 | recall@5 | MRR | ms/query | deps |
|---|---|---|---|---|---|---|
| `HashingEmbedder` (default, offline) | 0.30 | 0.50 | 0.50 | 0.38 | 0.7 | **0** |
| `FastEmbedEmbedder` (bge-small, ONNX) | 0.40 | 0.60 | **1.00** | 0.58 | 9.8 | `[fast]` |

### Live production recall (22 real memories, post-reindex)

| Query | HashingEmbedder | FastEmbed |
|---|---|---|
| "trading edge" | 0.22 | **0.79** |
| "database config" | 0.15 | **0.44** |
| "deploy rules" | 0.08 | **0.71** |

**Headline:** FastEmbed now default in MCP server + CLI (auto-fallback to HashingEmbedder if `fastembed` not installed). Recall quality up 3-4× on real data. WAL mode enabled for crash resilience.

```python
from continuityos import Memory
from continuityos.embedders import FastEmbedEmbedder
m = Memory("memory.db", embedder=FastEmbedEmbedder())   # pip install "continuityos[fast]"
```

## LoCoMo (public benchmark, 2026-07-02)

Full **LoCoMo** retrieval run (10 dialogues, 1977 questions): every dialogue turn ingested
as a memory, question must surface the gold *evidence turns* via hybrid recall. This measures
**evidence retrieval**, not LLM answer accuracy — do not compare directly with answer-graded
scores (Mem0 91.6, Memanto 87.1 are LLM-answer numbers).

| Embedder | R@1 | R@3 | R@5 | R@10 | MRR |
|---|---|---|---|---|---|
| HashingEmbedder (zero-dep default) | 0.281 | 0.434 | 0.483 | 0.535 | 0.368 |
| model2vec potion-base-8M (30MB, no torch) | 0.298 | 0.475 | 0.545 | 0.622 | 0.403 |

Reproduce: `python bench/locomo_bench.py` with `bench/data/locomo10.json` in place.
Honest read: the zero-dependency floor puts gold evidence in top-10 for ~54% of questions;
a 30MB static embedder lifts that to ~62% with no heavy deps. Real ONNX/ST embedders are
the next rung (`continuityos[fast]` / `[st]`).

## Honest notes
- Synthetic 10-pair set is a smoke benchmark, not a leaderboard. The harness is built so swapping in LoCoMo/LongMemEval is a one-function change — that's the next step before publishing competitive numbers vs Mem0 / Letta / Zep.
- `recall@1` gains are smaller than `recall@5` because the keyword (FTS) leg already wins rank-1 on exact-term queries; semantic helps most on paraphrases (where keyword misses) — exactly the hybrid thesis.
- `ms/query` is higher for ONNX (9.8ms) but still real-time; first call downloads the ~130MB model once.
