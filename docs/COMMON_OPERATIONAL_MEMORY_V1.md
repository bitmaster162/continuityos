# Common Operational Memory v1

Status: **shadow implementation**. Authority generation remains R63. Live cutover,
state apply, deployment, trading and capital effects remain disabled.

## Boundary

```text
Control Center  = accepted current truth and effect authority
ContinuityOS    = operational events, claims, decisions, checkpoints and replay
ArchiveOS       = immutable heavy source evidence
Return Broker   = physical delivery and byte custody
Dashboard       = deterministic projection only
Models/agents   = proposers and workers, never direct truth writers
```

This implementation deliberately does not expose an `apply` command. It cannot
write R63, Control Center current state, a return registry, a deployment target,
or trading state.

## Database location

Default:

- Windows: `%LOCALAPPDATA%\ContinuityOS\common_operational_memory_v1.db`
- Linux/macOS: `$XDG_STATE_HOME/continuityos/common_operational_memory_v1.db`
  or `~/.local/state/continuityos/common_operational_memory_v1.db`

The database must be local. DriveFS, Google Drive, OneDrive, network shares and
`00_RETURN_DROP` paths are rejected. SQLite uses WAL and `synchronous=FULL`.

## Data model

- `events`: append-only global SHA-256 chain. UPDATE/DELETE are blocked by SQLite triggers.
- `claims`: bi-temporal (`valid_from`, `valid_to`, `recorded_at`) with fixed-width UTC timestamps, an independent `snapshot --valid-at` query axis, and explicit
  evidence class and immutable supersession.
- `decisions`: proposed or authority-bound outcomes. ACCEPTED/REJECTED/HOLD
  require HUMAN or DETERMINISTIC_CONTROLLER authority, an authority receipt and
  immutable evidence references.
- `broker_custody`: physical return custody only. Imported rows are forced to
  `content_status=UNREVIEWED` and `apply_status=NOT_APPLIED`. Unknown source statuses fail down to
  `REPORTED`; arbitrary source values are not copied into the database.
- `checkpoints`: event cursor + deterministic projection SHA-256.

All five operational tables reject UPDATE and DELETE at the SQLite schema layer. Each custody
record also carries a full record hash in addition to the `(delivery_id, zip_sha256)` identity hash.

## CLI

```powershell
continuity-memory init
continuity-memory status
continuity-memory event --stream ops --type RUN_REPORTED --subject run-1 \
  --actor-type AGENT --actor-id FABLE-5 --payload '{"status":"reported"}'
continuity-memory claim --subject project-x --predicate runtime_status \
  --value '"UNKNOWN"' --evidence-state UNKNOWN --actor-id GPT
continuity-memory import-broker MASTER_RETURN_REGISTRY_R64.jsonl
continuity-memory snapshot --out operational_snapshot.json
continuity-memory snapshot --cursor 42 --valid-at 2026-07-31T20:00:00Z
continuity-memory checkpoint --label after-import
continuity-memory verify
```

Evidence CLI values use `SHA256:LOCATOR`.

## Status ceilings

Broker custody does not imply content acceptance. Model prose does not imply a
decision. The database cannot enable `can_trade`, cannot grant capital permission
and cannot apply a state delta. Deployment permission remains `DENY` and self-application remains
`false`. Those invariants are both schema- and test-bound.
