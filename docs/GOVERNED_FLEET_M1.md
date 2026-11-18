# Governed Fleet M1

Status: **candidate source implementation**. M1 is sequential multi-agent coordination only. It does not grant merge, deployment, runtime, destructive-storage, external-send, trading, wallet/order, or capital authority.

## Baseline

This candidate is built from protected ContinuityOS:

- commit `e499f54cc658604e29464fefc5694f68532cef75`
- tree `c1a92361fc1939f34986b811248eb59329e74555`
- source event: merge of Causal Spine PR #115 after exact independent review and SHA-bound owner gate.

## Architectural rule

`NO_SECOND_ADMISSION_LEDGER_OR_CURRENT_AUTHORITY`

Fleet M1 composes with existing primitives:

- `continuityos/gate/work_admission.py` remains source/scope/effect admission authority;
- `continuityos/gate/work_validation.py` remains admitted-command evidence execution and verification;
- `continuityos/gate/work_ledger.py` remains canonical append-only work lifecycle custody;
- `continuityos/current_work.py` remains the read-only project CURRENT projection.

`continuityos/gate/fleet_coordination.py` only adds deterministic relations needed for multi-agent work: Work Order v2.2 validation, Work Lease v1.2 binding/currentness, conflict serialization, dependency checks, scope/effect-expansion rejection, independent-verifier checks, checkpoint recovery, fan-in guards and a no-authority Fleet CURRENT projection.

Legacy `continuityos/agents.py` and `continuityos/orchestrator.py` are not widened into the governed authority model.

## M1 flow

```text
sealed Work Order
  -> existing work admission PASS
  -> Fleet dependency/conflict decision
  -> one active lease per conflict domain
  -> sequential worker output
  -> immutable/content-addressed coordination event
  -> existing canonical work ledger custody
  -> independent verifier
  -> serial integration queue candidate
  -> human/effect gate (outside M1)
```

`ALLOW` means only that the coordination preconditions are satisfied. It is not permission to merge, deploy, mutate runtime/storage, send externally, trade, access wallets, place orders or allocate capital.

## Work Order and Lease

Work Order v2.2 uses canonical full-document SHA-256:

`CANONICAL_JSON_UTF8_SHA256_FULL_DOCUMENT_V1`

A lease binds the exact Work Order ID and recomputed digest, exact resource scope, exact conflict keys, Git object format/base SHA and observed time interval. No heartbeat is inferred. An expired lease cannot be renewed by an activity label. A stale provider base holds the run.

Candidate writes remain serial in M1. Read-only and candidate-write leases are distinct; `EFFECT` lease mode is rejected.

## Conflict domains

Supported namespaces: `repo-path`, `git-branch`, `semantic`, `db`, `library-family`, `drive-object-set`, `deploy-target`, `runtime-service`, `authority-decision`, `effect-resource`.

`repo-path` conflicts are hierarchical: a prefix lease conflicts with a descendant path. Different files can still serialize through a shared `semantic:*` key.

## Independent verification

A verification receipt is rejected/held unless it binds the exact Work Order ID/digest, exact frozen worker-output digest, a different verifier run, isolated context, no hidden worker scratch transfer, no inherited worker conclusion as fact and fixed no-effect authority. `PASS_WITH_CONDITIONS` requires machine-readable conditions; plain `PASS` requires none.

## Checkpoints and recovery

Silence never implies a checkpoint or output. A disappeared worker produces HOLD. An existing immutable checkpoint remains evidence, but a successor must acquire a new run/lease identity and revalidate physical baseline.

## CURRENT projection

Fleet CURRENT is derived data with `projection_is_authority=false`, `provider_readback_precedence=true`, `execution_authority=NONE`, `can_trade=false`, `capital_permission=DENY`, `deploy_permission=DENY`, and no merge/deploy/destructive-storage/external-send authority. Physical provider evidence outranks stale projection.

## FleetBench M1

`bench/fleetbench_m1.py` deterministically exercises 15 adversarial classes: duplicate PR race, stale base, path/semantic writer conflicts, lease expiry, disappeared worker, self-verification, wrong-base output, missing/incompatible fan-in shards, effect escalation, provider change before effect, staging visibility reversal, stale owner gate and read-only write leakage.

The only candidate terminal after tests is `M1_CANDIDATE_READY_FOR_INDEPENDENT_REVIEW`. It does not mean merged, deployed, runtime-current, M2-ready, M3-ready or effect-ready.
