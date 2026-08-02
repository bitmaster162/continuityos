# GitHub Transition Gate v1

GitHub Transition Gate v1 adds two deterministic, effect-free controls to
ContinuityOS:

1. `continuity github-transition verify` physically admits one strict host
   closure / GitHub transport return.
2. `continuity memory-promotion evaluate` evaluates whether a compact memory
   candidate is eligible for a later human-controlled promotion decision.

Neither command pushes Git, applies R63/current state, mutates a registry,
merges, deploys, trades, accesses wallets, or uses capital.

## Verify one host-closure return

```bash
continuity github-transition verify \
  --zip FINAL_HOST_CLOSURE_AND_GITHUB_TRANSITION_R1_RETURN.zip \
  --sidecar FINAL_HOST_CLOSURE_AND_GITHUB_TRANSITION_R1_RETURN.zip.sha256 \
  --ready FINAL_HOST_CLOSURE_AND_GITHUB_TRANSITION_R1_RETURN.zip.READY_FOR_SYNC.json \
  --task-body-sha256 <controller-pinned-sha256>
```

The gate verifies:

- ZIP/SHA/READY identity and an exact non-aliased producer terminal;
- CRC, path safety, duplicates, case collisions, symlinks and size/ratio limits;
- exact work-order ID and task-body SHA across envelope and terminal state;
- manifest hashes, sizes and coverage of required evidence;
- nine slots (`CODEX-01` … `CODEX-08`, `WORK`), each left
  `UNREVIEWED / NOT_APPLIED`;
- repository visibility preservation, candidate branch HEAD/tree readback,
  no force push, no existing-default merge and secret-scan PASS;
- no-effect and teardown receipts.

Physical results are limited to:

```text
BYTE_VERIFIED
TRIPLET_INCOMPLETE
TASK_BINDING_INCOMPLETE
INVALID_RETURN
NOT_FOUND
```

A producer terminal ending in `REVISE` may still be `BYTE_VERIFIED`; physical
admission never rewrites it to PASS.

## Evaluate a memory promotion candidate

```bash
continuity memory-promotion evaluate \
  --closure-receipt GITHUB_TRANSITION_RECEIPT.json \
  --semantic-decisions SEMANTIC_DECISIONS.json
```

The semantic decision file is bound to the exact closure receipt bytes through
`closure_receipt_sha256`. The evaluator requires:

- a `BYTE_VERIFIED` COMPLETE closure;
- nine explicit GPT verdicts;
- `ACCEPT` / `PASS_WITH_CONDITIONS` only for physically byte-verified slots;
- all mandatory Wave A repositories and remote readbacks;
- R63 retained as authority;
- the memory branch retained as `NON_AUTHORITATIVE_CANDIDATE`;
- every no-apply/no-merge/no-secret global gate at PASS;
- `human_irreversible_approval=false`.

Even a successful result is only:

```text
PROMOTION_CANDIDATE_ELIGIBLE
```

It is not a promotion or human approval.
