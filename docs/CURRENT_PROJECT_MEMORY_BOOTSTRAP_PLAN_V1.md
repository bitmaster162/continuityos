# Current Project Memory Bootstrap Plan v1 (R39)

R39 is a read-only compiler between exact project evidence and the R38 fresh project-memory bootstrap gate.

## Purpose

`continuity-memory-bootstrap-plan --request REQUEST.json` runs only in a verified current session. It stable-reads each declared local evidence file, hashes the exact bytes, constructs an R38 bootstrap manifest, validates that manifest with the same R38 validator, and emits the exact canonical manifest JSON plus the SHA-256 of those exact UTF-8 bytes.

## Authority boundary

The plan is always `NOT_APPLIED`. It does not create a target database, issue an R38 bootstrap authorization, accept semantic assertions, modify OperationalMemory, mutate canonical state, deploy, dispatch agents, trade, or grant capital permission.

The request still declares project semantics. R39 verifies evidence bytes and manifest structure; it does **not** infer that the evidence proves the declared claim. A separate R38 authorization must bind the exact `manifest_file_sha256`, target database, claim count, and proposed-decision count before any fresh shadow database can be created.

## Deterministic handoff to R38

The successful plan contains both:

- `manifest`: parsed canonical manifest object;
- `manifest_canonical_json`: exact UTF-8 text to materialize as the R38 manifest file;
- `manifest_file_sha256`: SHA-256 of exactly `manifest_canonical_json.encode("utf-8")`.

Do not add a newline or reformat the canonical JSON before using its hash in an R38 authorization. Any byte change intentionally changes the manifest file SHA and must be re-authorized.

## Runtime ceiling

R39 requires verified current-session binding and remains read-only:

- `filesystem_write=false`
- `operational_memory_write=false`
- `canonical_mutation=false`
- `deployment=false`
- `can_trade=false`
- `capital_permission=DENY`

R38 remains the fresh-db effect gate; R36/R37 remain the synchronization path for an existing OperationalMemory database.
