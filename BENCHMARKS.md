# ContinuityOS — reproducible local benchmarks

## Default memory micro-benchmark

Run:

```bash
python bench/recall_bench.py
```

The included deterministic corpus contains 30 labeled query/target pairs, 100 distractors, and
20 fact-update pairs represented in old and new form: 170 memories total. The default
`HashingEmbedder` uses no API, model download, or external token call. The script rewrites
`bench/bench_results.json` with the measured result.

Local receipt from 2026-07-12 on the current Windows/Python 3.11 working tree:

| Metric | Result |
|---|---:|
| keyword recall@1 / @3 / @5 | 96.7% / 100.0% / 100.0% |
| paraphrase recall@1 / @3 / @5 | 30.0% / 53.3% / 60.0% |
| current-only knowledge update | 95.0% |
| temporal as-of | 100.0% |
| latency p50 / p95 / mean | 11.008 / 17.780 / 11.073 ms |
| external tokens / API calls | 0 / 0 |

Latency is hardware/load dependent. The synthetic corpus is a regression smoke, not a public
leaderboard or production-quality claim. In particular, the default embedder's paraphrase recall
is weak. Optional FastEmbed/model2vec/sentence-transformer configurations are supported, but this
repository does not currently ship a checksum-bound result artifact for them, so no comparative
gain is claimed here.

## LoCoMo status

`bench/locomo_bench.py` is a harness only. The required
`bench/data/locomo10.json` dataset is intentionally absent from the repository and no pinned
dataset checksum or raw result receipt is included. A missing dataset exits non-zero. Until those
artifacts are added, ContinuityOS publishes **no current LoCoMo score**.

## Governance corpus

The separate command below checks preflight decisions, not memory retrieval:

```bash
python -m bench.continuitybench
```

See [`BUILD_GATE_STATUS.md`](BUILD_GATE_STATUS.md) for its current local receipt and the boundary
claims that remain on hold.
