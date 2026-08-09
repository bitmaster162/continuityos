# Operational Memory Delta Proposal v1 (R36)

R35 lets a verified current session answer **what should this project do next?** while remaining read-only. R36 adds the safe return path: the session may prepare an exact proposal for how Common Operational Memory should change, but it still cannot change the database itself.

## Command

```text
continuity-memory-delta \
  --operational-db /path/to/common_operational_memory_v1.db \
  --request /path/to/delta-request.json
```

The command requires a verified current-session environment. It reads an existing Common Operational Memory database and the request file, verifies memory integrity, builds the R35 `current-work` capsule for the requested project, and prints one proposal JSON to stdout.

It never creates or updates the operational database and does not write an output file.

## Request

Schema:

```text
continuityos.operational_memory.delta_request/v1
```

Top-level fields are `schema`, `project_id`, `operations`, and optional `rationale`.

Supported operations:

- `RECORD_CLAIM`
- `SUPERSEDE_CLAIM`
- `RECORD_DECISION`
- `SUPERSEDE_DECISION`

A supersede operation must name a record that is **current in the exact project projection**. The compiler derives and binds its immutable claim/decision hash. A stale or foreign identifier is REVISE. The same target cannot be superseded twice in one proposal.

Evidence follows Common Operational Memory v1 rules. Non-`UNKNOWN` claim proposals require immutable evidence references. Terminal decision proposals (`ACCEPTED`, `REJECTED`, `HOLD`, `SUPERSEDED`) require immutable evidence and are marked `required_authority=HUMAN_OR_DETERMINISTIC_CONTROLLER`.

The proposal never assigns that authority to itself.

## Exact base binding

A PASS proposal records:

- OperationalMemory `projection_sha256`;
- `event_cursor`;
- `event_chain_head`;
- projection `valid_at`;
- R35 `current_work_capsule_sha256`;
- exact hashes of any superseded claims/decisions.

This prevents a later writer from treating the proposal as timeless. A future apply gate must reject the proposal if the memory base changed.

## Proposal only

The output explicitly states:

```text
apply_status=NOT_APPLIED
apply_implemented=false
execution_decision=HOLD
execution_authorized=false
```

and requires:

```text
base_projection_must_match_at_apply=true
event_chain_head_must_match_at_apply=true
superseded_record_hashes_must_match_at_apply=true
human_or_controller_review_required=true
apply_is_separate_effectful_operation=true
```

R36 intentionally does **not** implement the effectful apply path. That requires a separate authority boundary and stale-base check; weakening current R64 READ_ONLY / NO_FURTHER_AGENT_WORK to make proposal generation writable would defeat the current-session safety model.

No Control Center/R64 mutation, Drive mutation, deployment, agent dispatch, external message, trading, wallet access, order execution, or capital permission occurs. `can_trade=false`, `capital_permission=DENY`, `deploy_permission=DENY` remain unchanged.
