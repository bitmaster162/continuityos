# Current Operational Memory Apply Check v1 (R44)

R44 is the read-only point-in-time preflight immediately before the separate effectful R37 shadow-memory apply gate.

## Command

```text
continuity-memory-apply-check \
  --operational-db PROJECT.db \
  --proposal DELTA_PROPOSAL.json \
  --authorization APPLY_AUTHORIZATION.json
```

The command requires a verified current R64 session.

## Checks

R44 reuses the R37 proposal and authorization validators, then opens the existing OperationalMemory database read-only with `immutable=1`. A non-quiescent database with pending WAL frames is therefore refused rather than checkpointed.

The check verifies:

- exact proposal and authorization bytes/SHA binding;
- proposal identity and authorization structure;
- OperationalMemory integrity;
- exact projection/cursor/chain/current-work base;
- exact replay identity (`ALREADY_APPLIED`);
- current claim/decision supersession IDs and hashes;
- competing current claim or terminal-decision conflicts.

## Terminal meanings

- `CURRENT_MEMORY_APPLY_CHECK_READY`: point-in-time validation passed. This is **not** write permission.
- `CURRENT_MEMORY_APPLY_CHECK_ALREADY_APPLIED`: the exact proposal is already durably recorded.
- `CURRENT_MEMORY_APPLY_CHECK_REVISE`: artifacts, base, database, or operation targets failed validation.

R37 remains the only apply gate and must revalidate the exact inputs again under its own `BEGIN IMMEDIATE` write transaction.

R44 never modifies OperationalMemory, canonical state, Control Center truth, deployment, agent dispatch, trading, wallet state, or capital permissions. Authorization record validation does not claim cryptographic authentication of the authority identity.
