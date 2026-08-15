# Project Update Post-Preflight Materializer v1

This surface closes the filesystem handoff between the merged packet-aware project-update preflight and the existing unbound R37 apply gate.

Command:

`continuity-project-update-materialize-ready --packet R52_PACKET.json --authorization COMPLETED_AUTHORIZATION.json --preflight PREFLIGHT_READY.json --output-dir REVIEW_DIR`

The command is intentionally **post-preflight**. It does not recreate the older R54 flow that materialized an incomplete authorization skeleton before a decision. Instead it requires a saved `CURRENT_PROJECT_UPDATE_PREFLIGHT_READY` result produced from the exact packet and exact completed authorization bytes.

Before any write it verifies:

- no CURRENT/REVISE session binding is active; materialization is an unbound filesystem effect;
- the R52 packet is valid and its exact proposal bytes still pass the current proposal validator;
- the completed authorization still passes the current R37 authorization validator for those exact proposal bytes;
- the saved preflight is `CURRENT_PROJECT_UPDATE_PREFLIGHT_READY` with `apply_ready=true` and `apply_status=NOT_APPLIED`;
- packet ID, proposal ID, proposal SHA, authorization SHA and authorization identity all match the saved preflight;
- the preflight CLI input hashes and sizes match the exact packet and authorization files now presented;
- the saved preflight records a verified CURRENT session and still requires a separate unbound R37 revalidation;
- the output parent is canonical and the output directory does not already exist.

A successful fresh directory contains:

- `OPERATIONAL_MEMORY_DELTA_PROPOSAL.json` — exact proposal bytes bound by R52 and preflight;
- `OPERATIONAL_MEMORY_APPLY_AUTHORIZATION.json` — exact completed authorization bytes bound by preflight;
- `CURRENT_PROJECT_UPDATE_PREFLIGHT_READY.json` — exact saved preflight receipt bytes;
- `MATERIALIZATION_RECEIPT.json` — non-applying filesystem handoff receipt;
- `SHA256SUMS.txt` — hashes of the four artifacts above.

The materializer never writes OperationalMemory, mutates accepted truth or canonical state, deploys, dispatches, trades, accesses a wallet, or grants execution/capital permission. A partial write is rolled back by deleting the newly owned output directory.

The next gate remains R37, run **unbound**, and R37 must re-read and revalidate the exact materialized proposal and authorization bytes before any effectful apply.
