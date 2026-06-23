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

## Honest notes
- Synthetic 10-pair set is a smoke benchmark, not a leaderboard. The harness is built so swapping in LoCoMo/LongMemEval is a one-function change — that's the next step before publishing competitive numbers vs Mem0 / Letta / Zep.
- `recall@1` gains are smaller than `recall@5` because the keyword (FTS) leg already wins rank-1 on exact-term queries; semantic helps most on paraphrases (where keyword misses) — exactly the hybrid thesis.
- `ms/query` is higher for ONNX (9.8ms) but still real-time; first call downloads the ~130MB model once.
