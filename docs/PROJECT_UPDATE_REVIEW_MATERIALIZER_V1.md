# Project Update Review Materializer v1 (R54)

R54 removes manual copying between the merged R52 review packet and the later R44/R37 gates without granting authority.

Command:

`continuity-project-update-materialize --packet R52_PACKET.json --output-dir REVIEW_DIR`

The command is effectful only on a new local review directory and therefore refuses any declared current R64 session before reading the packet or creating output. It runs only in an unbound process.

Before writing, R54 verifies:

- the packet is an exact `CURRENT_PROJECT_UPDATE_REVIEW_PASS` packet;
- its `packet_id` matches the canonical R52 body;
- authorization remains not granted and identity remains unauthenticated;
- the embedded proposal text hashes to the advertised proposal SHA;
- the proposal is canonical and passes the exact R37 proposal validator;
- the embedded authorization skeleton is exactly the deterministic R52 skeleton for those proposal bytes;
- the skeleton still fails the exact R37 authorization validator;
- the output parent is canonical and does not traverse a symlink/junction/alias ancestor;
- the output directory does not already exist.

A successful fresh directory contains:

- `OPERATIONAL_MEMORY_DELTA_PROPOSAL.json` — exact proposal bytes whose SHA is already bound by R52;
- `OPERATIONAL_MEMORY_APPLY_AUTHORIZATION_SKELETON.json` — intentionally incomplete and R37-invalid;
- `MATERIALIZATION_RECEIPT.json` — non-authorizing handoff receipt;
- `SHA256SUMS.txt` — hashes of the three artifacts above.

R54 never fills `decision`, `authority_class`, `authority_id`, `authority_ref`, `apply_recorded_at`, or `rationale`. It does not authenticate an authority identity, write OperationalMemory, call R44, call R37, mutate R64/Drive/canonical state, deploy, dispatch, trade, access a wallet, or grant capital permission.

The next gate remains a separate HUMAN or DETERMINISTIC_CONTROLLER decision, followed by R44 read-only preflight and only then the R37 effectful apply gate.
