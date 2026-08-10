# Current Project Update Review v1 (R52/R53)

`continuity-project-update-review --db PROJECT.db --request CLAIM_SYNC_REQUEST.json` is a verified-current-session, read-only operator surface for updating existing project memory.

It composes the already-merged project-memory layers into one review packet:

1. R35 current project/work view;
2. R43 logical claim selector resolution and exact evidence rehash;
3. R51 target-bound R36 delta proposal;
4. exact canonical proposal bytes and proposal-file SHA-256;
5. an intentionally incomplete R37 authorization skeleton;
6. the required next gate: separate authority decision, then R44 preflight, then R37 effectful apply from an unbound process.

## Authority boundary

The packet is always `NOT_APPLIED`. It does not fill `decision`, `authority_class`, `authority_id`, `authority_ref`, `apply_recorded_at`, or authority rationale. The emitted skeleton is deliberately required to fail the real R37 authorization validator until those fields are supplied by a separate HUMAN or DETERMINISTIC_CONTROLLER action.

The command does not create proposal/auth files, mutate OperationalMemory, accept semantic assertions, modify canonical state, deploy, dispatch an agent, trade, access a wallet, or grant capital permission.

## Exact proposal materialization

`proposal.proposal_canonical_json` is the exact UTF-8 payload to materialize for downstream review. `proposal.proposal_file_sha256` is computed over exactly those bytes, with no implicit trailing newline. Any byte change produces a different SHA and requires a new authorization review.

The nested proposal contains verified `operational_memory` target metadata. R51 therefore makes authorization of the exact proposal-file SHA an indirect binding to the exact canonical DB target as well as the exact base state.

## R53 full-base freshness recheck

R52 originally re-read only the project-scoped `current-work` capsule after R43 built the proposal. That catches changes which alter the selected project's work view, but an unrelated subject in the same OperationalMemory database can move the global projection SHA, event cursor, and event-chain head without changing that project capsule. In that case the R36 proposal is already stale even though the project work capsule is unchanged.

R53 keeps the R52 work-capsule check and adds a second immutable read-only snapshot of the exact target DB. Before returning `CURRENT_PROJECT_UPDATE_REVIEW_PASS`, the command requires the complete R37 base identity to match the proposal exactly: `projection_sha256`, `event_cursor`, `event_chain_head`, and `current_work_capsule_sha256`. Any drift returns `REVIEW_PACKET_BINDING_FAILED` before proposal bytes or an authorization skeleton are presented for review.

R44 and R37 still re-read and revalidate at their own gates; R53 only prevents an already-stale proposal from being presented as ready for authority review.

## Why this exists

Before R52 the same safe workflow required the operator to run and manually connect R43, proposal materialization/hashing, R45 authorization-request preparation, R44 preflight and R37 apply. R52 removes the manual claim-id/hash and proposal-SHA glue while preserving the authority/effect boundary. R53 closes the remaining whole-database snapshot gap in that composed review step.
