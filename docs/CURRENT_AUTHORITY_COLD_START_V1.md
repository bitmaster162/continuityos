# Current Authority Cold-Start v1

This is the current ContinuityOS fresh-session protocol for an already-promoted control generation such as R64. It is deliberately separate from the historical R63 ANTI_AMNESIA cold-start schema.

## Why it exists

The historical cold-start implementation is cryptographically and semantically bound to R63. Wrapping that implementation in a newer state-resolution gate does not make its generated challenge current-authority aware. This protocol removes that hidden R63 dependency for the normal installed path.

## Required current inputs

`continuity cold-start prepare` in current mode requires all of the following:

- `--state-bundle`: one bounded `continuityos.state_resolution.bundle/v1`;
- `--authority-pointer`: the exact current `CURRENT_POINTER.json` bytes;
- `--authority-pointer-sha256`: controller-pinned SHA-256 of those pointer bytes;
- `--current-state`: exact `CURRENT_STATE.json` bytes;
- `--role-index`: exact `ROLE_INDEX.json` bytes;
- `--role-views`: exact `ROLE_VIEWS.json` bytes;
- `--spec`: one controller-authored `CONTINUITYOS_CURRENT_COLD_START_SPEC_V1`;
- `--output`: a new output directory.

The pointer must be `canonical_activation.status=ACTIVE`, its provider readback must report exact stable roots, and the supplied root bytes must match the SHA-256 identities carried by the pointer.

## Immutable pre-promotion markers

A promoted pointer may activate immutable root bytes that were compiled before human approval. For example, the R64 `CURRENT_STATE.json` contains the compilation-time marker `CANDIDATE_NOT_ACTIVE_PENDING_ROBERT` even though the exact accepted pointer later records `canonical_activation.status=ACTIVE`.

The current protocol does **not** rewrite such root bytes. It binds both facts into the capsule:

1. the exact immutable compiled marker; and
2. the exact ACTIVE pointer whose activation record supersedes that marker for canonicality only.

This follows the R64 promotion semantics rather than treating a stale string inside an immutable root as current authority.

## State resolution

The R18 state resolver remains mandatory. A stale/lower-authority `OPEN` template cannot roll back a later accepted decision. A fresh current provider/audit contradiction blocks cold-start before output creation.

Only operational `PASS` or `PASS_WITH_CONDITIONS` state is admissible.

## Effect ceiling

Current cold-start is intentionally narrower than the historical generic spec:

- `effect_ceiling=READ_ONLY` only;
- `auto_dispatch=false`;
- no repository writes;
- no archive access;
- no deployment;
- no current/canonical state apply;
- no self-application;
- `can_trade=false`;
- `capital_permission=DENY`;
- `deploy_permission=DENY`.

`NO_FURTHER_AGENT_WORK=true` in the current pointer is preserved, not relaxed. Preparing a deterministic read-only context challenge does not dispatch an agent or grant execution authority.

## Prepare

```bash
continuity cold-start prepare \
  --state-bundle STATE_BUNDLE.json \
  --authority-pointer CURRENT_POINTER.json \
  --authority-pointer-sha256 <exact-pointer-sha256> \
  --current-state CURRENT_STATE.json \
  --role-index ROLE_INDEX.json \
  --role-views ROLE_VIEWS.json \
  --spec CURRENT_COLD_START_SPEC.json \
  --output CURRENT_COLD_START
```

A legacy `--boot-receipt` is rejected in current mode because current preparation binds the stable roots directly.

## Verify

`continuity cold-start verify` auto-detects `CONTINUITYOS_CURRENT_COLD_START_CHALLENGE_V1` and uses the current exact-ACK verifier. Historical R63 challenge schemas continue to use the historical verifier.

## Historical compatibility

Historical R63-unbound preparation remains available only through explicit compatibility intent:

```bash
continuity cold-start prepare \
  --legacy-r63-unbound \
  --boot-receipt R63_BOOT_RECEIPT.json \
  --spec R63_SPEC.json \
  --output R63_COLD_START
```

The compatibility path does not acquire current R64 authority merely because it is still executable.
