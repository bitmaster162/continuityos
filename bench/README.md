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
**not** publish a current LoCoMo/LongMemEval leaderboard number because the dataset
and a checksum-bound raw result are not shipped in this repository. Canon: ship
only reproducible numbers.

Last local run (default embedder, 170-memory corpus):
keyword recall@1 96.7% · paraphrase recall@1 30% · knowledge-update 95% ·
temporal as-of 100% · recall p50 11.008 ms · 0 external tokens. Latency is
hardware/load dependent; `bench_results.json` is the machine-readable receipt.

## Governance regression corpus

```bash
python -m bench.continuitybench
```

This command checks 30 hand-labeled decisions plus eight obfuscated examples and exits non-zero
on a mismatch; CI runs it. It is a regression floor for the explicitly mediated paths, not proof
of mandatory interception, out-of-distribution detection, compliance, or production safety. See
[`BUILD_GATE_STATUS.md`](../BUILD_GATE_STATUS.md) for the current measured result and open holds.
