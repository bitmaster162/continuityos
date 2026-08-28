# ContinuityOS benchmarks

Honest, reproducible, zero-external-call baseline:

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

Last legacy local run (default embedder, 170-memory corpus):
keyword recall@1 96.7% · paraphrase recall@1 30% · knowledge-update 95% ·
temporal as-of 100% · recall p50 11.008 ms · 0 external tokens. Latency is
hardware/load dependent. `bench_results.json` is a legacy machine-readable result,
not a sealed current-head certification: it does not bind repository HEAD/tree,
benchmark source, environment, or external model bytes.

## Sealed benchmark proof runners

The strict runners preserve the legacy commands while adding checksum-bound result
and manifest output. Write outputs outside the checkout when you want
`working_tree_clean=true` in the manifest.

### Embedded recall/current-truth corpus

HashingEmbedder is fully bound by tracked code:

```bash
python bench/recall_sealed.py \
  --embedder hashing \
  --json-out /tmp/recall-result.json \
  --manifest-out /tmp/recall-manifest.json
```

A production semantic embedder additionally requires an exact model revision and a
caller-supplied SHA-256 declaration for the intended model bytes/artifact:

```bash
python bench/recall_sealed.py \
  --embedder fastembed \
  --model BAAI/bge-small-en-v1.5 \
  --model-revision <immutable-revision> \
  --model-sha256 <64-hex-sha256> \
  --json-out /tmp/recall-fast-result.json \
  --manifest-out /tmp/recall-fast-manifest.json
```

For non-hashing embedders R1 records this as `DECLARED_MODEL_DIGEST`. The runner
validates the digest syntax and records it with the model revision and installed
package version, but it does **not** compute a digest over the model snapshot that
the backend actually loads. Therefore R1 must not be described as cryptographic
proof that loaded model bytes match the declared SHA-256. Stronger snapshot-byte
verification is a separate future assurance layer.

The sealed result contains per-case keyword/paraphrase hits and current/as-of
checks. The manifest binds the benchmark source SHA-256, Git HEAD/tree, embedded
corpus digest, exact installed package versions, declared model identity, argv,
result SHA-256, platform/Python identity, and an explicit zero-authority ceiling.

### LoCoMo retrieval

The repository does not ship the LoCoMo dataset. Obtain the intended
`locomo10.json` independently, compute/verify its SHA-256, and run:

```bash
python bench/locomo_sealed.py \
  --data /path/to/locomo10.json \
  --expected-sha256 <64-hex-dataset-sha256> \
  --embedder hashing \
  --json-out /tmp/locomo-result.json \
  --manifest-out /tmp/locomo-manifest.json
```

For FastEmbed/Model2Vec/SentenceTransformers, add `--model-revision` and
`--model-sha256`; strict R1 sealing fails closed without both declarations. The
same `DECLARED_MODEL_DIGEST` limitation above applies: the runner does not verify
that backend-loaded snapshot bytes match the supplied digest. The result stores
raw per-question gold evidence IDs, ranked evidence IDs, first-gold rank, Recall@k
and MRR. A dataset hash mismatch stops before evaluation.

### CurrentTruthBench

The offline regression corpus freezes real stale-projection classes observed in
this repository, including Issue #111/#114 coordination text versus merged PR #115
provider metadata and historical `BUILD_GATE_STATUS.md` versus a newer protected
`master` readback:

```bash
python -m bench.current_truth_bench \
  --json-out /tmp/current-truth.json \
  --manifest-out /tmp/current-truth-manifest.json
```

It also covers a later fresh provider contradiction against an older human PASS
and an equal-authority provider conflict. These are deterministic regression
fixtures only: they never replace a fresh provider readback for a live decision.
The result/manifest grant zero execution or provider-effect authority.

### Causal governance proof

`CausalBench` already supports immutable JSON output and does not need a second
runner:

```bash
python -m bench.causalbench --json-out /tmp/causalbench.json
```

For a CI-style command receipt, wrap that existing command with
`python -m tools.ci_review run ...` and include the result in the normal
`receipt-manifest` path. The benchmark pass grants no source, merge, deployment,
runtime, provider-effect, trading, wallet, order, or capital authority.

Structured provider readback for a physical fact must outrank stale coordination
prose. A later fresh physical contradiction blocks reliance on an older accepted
decision rather than silently manufacturing higher authority.

## Governance regression corpus

```bash
python -m bench.continuitybench
```

This command checks 30 hand-labeled decisions plus eight obfuscated examples and
exits non-zero on a mismatch; CI runs it. It is a regression floor for the
explicitly mediated paths, not proof of mandatory interception,
out-of-distribution detection, compliance, or production safety.

[`BUILD_GATE_STATUS.md`](../BUILD_GATE_STATUS.md) contains historical measured
receipts and open holds. Its dated status must not be treated as current provider
truth without a fresh repository/provider readback.
