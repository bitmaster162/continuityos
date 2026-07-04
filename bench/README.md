# ContinuityOS benchmarks

Honest, reproducible, zero-external-call. Run:

```bash
python bench/recall_bench.py
```

`recall_bench.py` measures what CoS is actually built for, on the **default
zero-dep HashingEmbedder** (no API keys, deterministic):

- **Recall@k** — keyword vs paraphrase (paraphrase is intentionally weak on the
  default embedder; `pip install continuityos[fast]` lifts it).
- **Knowledge-update / temporal correctness** — after a fact is superseded, does
  `current_only` return the NEW value and `as_of=<old>` return the OLD one?
  LoCoMo has **no** knowledge-update questions; this is CoS's core wedge.
- **Latency** p50/p95 and **external token cost** (0 — fully local).

All numbers are measured at run time and written to `bench_results.json`. We do
**not** publish a LoCoMo/LongMemEval leaderboard number — see
`HANDOFF/COMPETITIVE_LANDSCAPE_AND_BENCHMARKS_20260705.md` for why the category's
headline scores are actively disputed (Zep 84% → 58.44% → 75.14%). Canon: ship
honest numbers.

Last local run (default embedder, 170-memory corpus):
keyword recall@1 96.7% · paraphrase recall@1 30% · knowledge-update 95% ·
temporal as-of 100% · recall p50 ~4 ms · 0 external tokens.
