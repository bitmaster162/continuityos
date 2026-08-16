# SCT-R2 — TwinBench Arena

## Purpose

TwinBench Arena is the first longitudinal evaluation harness for the Sovereign Cognitive Twin.
It answers a narrow question with evidence instead of adjectives:

> Does a personalized ContinuityOS twin predict the principal's real decisions better than weaker baselines?

The arena is shadow-only. It does not execute actions, mutate authority, train models, or grant capabilities.

## Blind protocol

For each real decision case:

```text
freeze case + allowed inputs
→ hash each contestant input snapshot
→ open arena case
→ every contestant commits prediction + confidence
→ block human reveal until all commits exist
→ reveal one human decision
→ score every contestant against that same reveal
→ retain append-only evidence
```

A contestant can be any stable system configuration, for example:

- `generic`: frontier model with only the decision prompt;
- `profile_rag`: frontier model plus static profile / retrieval context;
- `sct`: ContinuityOS Twin / Decision Twin with the permitted personal context.

Use stable contestant IDs that identify the tested configuration. The `input_snapshots` map records SHA-256 digests of the exact input artifacts supplied to each contestant before prediction.

## Anti-hindsight guarantees

- Predictions cannot be submitted before the case opens.
- The human outcome cannot be revealed until every registered contestant has committed.
- Predictions are rejected after reveal.
- Duplicate contestant submissions are rejected.
- One shared human reveal is used to derive every contestant's R1 evaluation.
- Case spec and reveal payloads are content-addressed.
- The inherited R1 ledger remains append-only and hash-chained.
- Tamper causes verification failure and blocks later append operations.

This prevents the easiest benchmark fraud: changing context, predictions, or the target after seeing the answer.

## Metrics

Per case:

- predicted choice;
- correctness;
- confidence;
- absolute calibration error;
- Brier-style squared calibration error;
- escalation flag.

Longitudinal leaderboard:

- case count;
- accuracy;
- mean confidence;
- mean absolute calibration error;
- mean Brier error;
- escalation rate.

A contestant is not leaderboard-eligible until `min_cases` is reached. A winner is not emitted when eligible contestants do not cover the same evaluated case set.

Pairwise reports use only common evaluated cases and return:

- A-only correct;
- B-only correct;
- both correct;
- both wrong;
- accuracy delta;
- mean Brier error for each contestant.

## Invariants

```text
Twin Prediction != Human Decision
Twin != Authority
Benchmark Input != Mutable After Prediction
Human Reveal != Available Before All Commits
Parameter / Memory Access != Permission
```

Every arena case remains:

```text
mode = SHADOW
execution_authority = NONE
can_execute = false
```

## Explicit non-goals

R2 does not decide that SCT is better after one or two examples. It does not define a universal statistical threshold, does not call external models itself, and does not automate delegation.

The arena records evidence. The next experiment supplies real blind cases.

## Next evidence gate

Run real decisions using at least the three baseline configurations above. Preserve the exact input snapshot for every contestant and commit every prediction before the principal answers.

Do not promote SCT toward delegated execution merely because it wins a small benchmark. Prediction gain, calibration, escalation quality, security and governance remain separate gates.
