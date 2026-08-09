# Current Project Memory Bootstrap Check v1 (R41)

R41 closes the read-only verification gap between the R39 bootstrap-plan compiler and the separate R38 effectful fresh-database bootstrap.

## Command

```text
continuity-memory-bootstrap-check \
  --db /local/path/project.db \
  --manifest /local/path/bootstrap-manifest.json \
  --authorization /local/path/bootstrap-authorization.json
```

The command requires an already verified current session. It has no legacy fallback.

## What it verifies

At one point in time, R41 reuses the R38 validators to verify:

- exact raw manifest bytes and schema;
- exact raw authorization bytes and binding to the manifest SHA, project, target path and row counts;
- every declared evidence file and SHA-256;
- the R40 canonical target-parent invariant;
- target availability, or an exact already-published bootstrap when a target already exists.

A successful absent-target result is `CURRENT_BOOTSTRAP_CHECK_READY`. An exact existing bootstrap returns `CURRENT_BOOTSTRAP_CHECK_ALREADY_CREATED`. Any mismatch is `CURRENT_BOOTSTRAP_CHECK_REVISE`.

Existing targets are inspected with SQLite `immutable=1`, not ordinary `mode=ro`, so the preflight cannot create `-shm` or `-wal` sidecars while claiming `filesystem_write=false`. A target with pending non-empty WAL frames is deliberately not inspected immutably and therefore revises fail-closed; the separate R38 effectful gate must make the final decision after its own fresh validation.

## Authority and effect boundary

`READY` is not an execution grant. R41 always reports `execution_decision=HOLD` and `execution_authorized=false`. It performs no OperationalMemory write, filesystem write, canonical-state mutation, deployment, agent dispatch, external message, wallet/trading action, or capital operation.

The R38 authorization record remains an explicit local authority record, not an authenticated cryptographic identity. R41 therefore reports `authorization_record_valid=true` only when its structure and exact bindings validate, while `authorization_identity_authenticated=false` remains explicit.

The result is point-in-time only. Filesystem and evidence state can change after preflight. The separate R38 effectful gate remains mandatory and must re-read and revalidate all artifacts, evidence and target conditions immediately before publication.
