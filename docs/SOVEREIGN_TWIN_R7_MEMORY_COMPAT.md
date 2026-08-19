# Sovereign Twin R7 — Memory Compatibility Gate

Purpose: prevent an existing ContinuityOS memory database from silently mixing vector spaces when Sovereign Twin switches to the local LM Studio Nomic embedding model.

`sovereign-twin memory-compat` is read-only. It probes the selected local embedding model, inventories stored vector dimensions, checks the optional `twin-memory-manifest.json`, and emits one verdict:

- `READY_NO_STORED_VECTORS`
- `COMPATIBLE_MANIFEST_BOUND`
- `DIMENSION_MATCH_UNBOUND_SEMANTICS`
- `REEMBED_REQUIRED_DIMENSION_MISMATCH`
- `BLOCKED_MIXED_VECTOR_DIMENSIONS`

Matching dimension alone is not treated as proof that vectors came from the same embedding model. Canonical memory is never mutated by this audit.

Boundary remains `can_execute=false`, `execution_authority=NONE`. This is product/runtime engineering only; no R13 scientific calls or Case #001 operations.
