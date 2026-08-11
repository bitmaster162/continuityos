# Operational Memory Authorized Apply v1 (R37)

R36 deliberately stops at `apply_status=NOT_APPLIED`. R37 adds the separate effectful boundary that can apply one exact R36 proposal to **shadow Common Operational Memory only**.

It does not make a current R64 session writable. The opposite rule is enforced: if any current-session binding is declared, `continuity-memory-apply` fails closed before opening the operational database writable.

## Command

```text
continuity-memory-apply \
  --operational-db /path/to/common_operational_memory_v1.db \
  --proposal /path/to/r36-proposal.json \
  --authorization /path/to/apply-authorization.json
```

The command is intended for a separate, explicitly effectful, unbound process. It never applies Control Center state, canonical R64 state, deployment state, trading state, wallet state, or capital permissions.

## Authorization artifact

Schema:

```text
continuityos.operational_memory.apply_authorization/v1
```

Exact fields:

- `schema`
- `decision=APPROVE_SHADOW_MEMORY_APPLY`
- `proposal_id`
- `proposal_file_sha256`
- `project_id`
- `base_projection_sha256`
- `base_event_cursor`
- `base_event_chain_head`
- `operation_count`
- `authority_class`
- `authority_id`
- `authority_ref`
- `apply_recorded_at`
- `rationale`

`authority_class` must be `HUMAN` or `DETERMINISTIC_CONTROLLER`. The authorization binds the **raw proposal file SHA-256**, not merely its parsed fields.

The artifact is an explicit local authority record, not a cryptographic signature. Environments that require cryptographic identity must wrap or replace this authority record with an authenticated mechanism before treating it as an external security boundary.

## Stale-base rule

Before any write, R37 verifies:

- OperationalMemory integrity;
- exact proposal identity and deterministic `proposal_id`;
- exact authorization identity;
- proposal raw-file SHA;
- project identity;
- projection SHA;
- event cursor;
- event-chain head;
- R35 current-work capsule SHA;
- exact hashes of superseded claims/decisions.

The logical base is checked once read-only and again **after `BEGIN IMMEDIATE` acquires the write lock**. Any mismatch is REVISE.

## Atomicity

All proposal operations are applied using one SQLite transaction:

```text
BEGIN IMMEDIATE
  operation 0
  operation 1
  ...
  MEMORY_DELTA_APPLIED event
  verify OperationalMemory
COMMIT
```

If any operation or verification fails, the transaction rolls back. No partial delta and no durable apply receipt may remain.

The final `MEMORY_DELTA_APPLIED` event binds:

- proposal ID;
- proposal raw SHA;
- authorization raw SHA;
- exact base identity;
- operation result identities/hashes;
- `accepted_truth_modified=false`;
- `canonical_state_modified=false`.

Exact replay of an already applied proposal is idempotent and returns `CURRENT_MEMORY_APPLY_ALREADY_APPLIED` without appending a second apply event.

## Split-brain protections

R37 applies stricter rules than a raw sequence of `record_claim()` / `record_decision()` calls:

- `RECORD_CLAIM` cannot create a second current claim with the same subject/predicate/scope; use `SUPERSEDE_CLAIM`.
- supersession must bind the exact current record hash and an unsuperseded target.
- a terminal `RECORD_DECISION` cannot coexist with another current terminal decision of the same subject/type; use `SUPERSEDE_DECISION`.
- standalone `RECORD_DECISION state=SUPERSEDED` is refused.

These checks occur inside the same locked transaction as the write.

## Current-session rule

A verified current R64 session remains:

```text
READ_ONLY
NO_FURTHER_AGENT_WORK
```

Therefore, with current-session environment variables present, R37 returns HOLD/REVISE and performs no memory write. Proposal generation remains available through R36; applying it must happen through a separately authorized unbound process.

## Effect ceiling

A successful R37 receipt may report `operational_memory_write=true`, because the shadow database actually changed. It must simultaneously retain:

- `accepted_truth_modified=false`
- `current_state_apply=false`
- `canonical_mutation=false`
- `deployment=false`
- `agent_dispatch=false`
- `external_message=false`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

R37 does not promote Common Operational Memory into Control Center authority.