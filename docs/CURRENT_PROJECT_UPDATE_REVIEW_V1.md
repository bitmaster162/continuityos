# Current Project Update Review v1 (R52)

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

## Why this exists

Before R52 the same safe workflow required the operator to run and manually connect R43, proposal materialization/hashing, R45 authorization-request preparation, R44 preflight and R37 apply. R52 removes the manual claim-id/hash and proposal-SHA glue while preserving the authority/effect boundary.
