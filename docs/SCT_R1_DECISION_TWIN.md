# SCT-R1 — Shadow Decision Twin

## Purpose

SCT-R1 is the smallest falsifiable Decision Twin slice for ContinuityOS. It does not try to
be a full digital person and it does not execute actions. It creates a durable evidence loop:

```text
frozen situation
→ prediction committed before the human answer
→ later human decision
→ prediction-vs-reality evaluation
→ longitudinal metrics
```

The cognition that produces a candidate prediction is deliberately outside this module. It may
come from `continuityos.twin.Twin`, a frontier model, a local model, or a deterministic rule
engine. SCT-R1 owns the evidence contract so model replacement does not destroy evaluation
continuity.

## Invariants

- `Twin Prediction != Human Decision`.
- `Twin != Authority`.
- Every prediction is `mode=SHADOW`, `execution_authority=NONE`, `can_execute=false`.
- The prediction is committed before the human decision is accepted.
- Prediction and human-decision IDs hash their exact semantic contents.
- Ledger events are append-only JSONL entries chained by SHA-256.
- A corrupted ledger refuses later append operations.
- Wrong predictions remain visible; they are scored, not rewritten after seeing the answer.

## R1 records

`TwinPrediction` contains the case, frozen situation, explicit choice set, predicted choice,
confidence, reasons, evidence references, conditions that would change the answer, escalation
intent, optional twin snapshot/model IDs, timestamp and content-addressed prediction ID.

`HumanDecision` binds one later human choice to the committed prediction ID.

`TwinEvaluation` records correctness and calibration error after the human answer.

`ShadowDecisionLedger` persists the ordered prediction → decision → evaluation evidence chain and
returns aggregate accuracy/calibration/escalation metrics without inventing universal thresholds.

## Explicit non-goals

SCT-R1 does **not**:

- infer execution permission;
- call tools or external services;
- modify ContinuityOS canon, authority, policy or grants;
- train or fine-tune a model;
- promote model inference to human truth;
- claim cryptographic non-repudiation or protection against a host compromise;
- provide multi-process locking or a production transparency log.

Those are later phases and require separate evidence gates.

## Next evidence gate

Run shadow predictions on real decisions with the prediction committed before the human answer.
Compare at minimum:

1. generic frontier-model baseline;
2. static profile/RAG baseline;
3. ContinuityOS Twin/SCT candidate.

Do not expand delegation until longitudinal evidence shows useful predictive/calibration gain.
