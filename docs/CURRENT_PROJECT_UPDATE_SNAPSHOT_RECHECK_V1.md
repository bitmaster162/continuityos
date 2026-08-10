# Current Project Update Snapshot Recheck v1 (R53)

R53 hardens the merged R52 project-update review packet against a narrow stale-snapshot race.

R52 already re-read the target project's `current-work` capsule after R43 claim-sync planning. That catches changes which alter the target project's work view. It does not catch an unrelated OperationalMemory event which moves the global R36 base (`projection_sha256`, `event_cursor`, `event_chain_head`) while leaving the target project capsule unchanged.

R53 installs a lazy post-import guard over the existing R52 builder. After an R52 PASS candidate is assembled, the guard performs one final read-only OperationalMemory projection and compares, from that one coherent snapshot:

- `projection_sha256`
- `event_cursor`
- `event_chain_head`
- `current_work_capsule_sha256`

All four must equal the nested R36 proposal base. Any mismatch returns `CURRENT_PROJECT_UPDATE_REVIEW_REVISE` with reason `REVIEW_PACKET_SNAPSHOT_STALE`.

On PASS, R53 adds a `snapshot_recheck` record and recomputes the packet id. Proposal bytes, proposal SHA and the intentionally incomplete R37 authorization skeleton are unchanged.

This is a read-only consistency check only. It grants no authority, performs no OperationalMemory write, and does not replace the later R44 preflight or R37 effectful apply gate. A change after the final R53 read is still caught by the later exact R44/R37 base revalidation.
