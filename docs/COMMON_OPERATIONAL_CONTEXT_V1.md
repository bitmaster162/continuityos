# Common Operational Context v1

Common Operational Context v1 is a deterministic, bounded, read-only projection
from Common Operational Memory for one verified Anti-Amnesia session capsule.

```text
SESSION_CAPSULE.json
+ controller-authored context spec
+ named memory checkpoint
+ immutable local SQLite read
→ canonical context pack
→ exact byte verifier
```

## Ownership boundaries

- **Control Center** owns accepted current truth and authority.
- **ContinuityOS** owns append-only operational events, checkpoints and replay.
- **ArchiveOS** owns immutable heavy source evidence.
- **Return Broker** owns physical delivery.
- The context pack is a projection only; it cannot accept content or apply state.

## Safety properties

- R63 authority and session capsule SHA are bound exactly.
- A named checkpoint fixes the event cursor.
- Subjects, predicates, evidence classes and decision states are explicit.
- Count and byte budgets fail closed; no silent truncation occurs.
- SQLite is opened with `mode=ro&immutable=1` only after a quiescent-WAL check.
- Broker data is aggregate-only and remains `UNREVIEWED` / `NOT_APPLIED`.
- Output is canonically serialized and independently reproducible.
- No state-apply, deployment, trading, capital or self-application API exists.

## CLI

```powershell
continuity-context prepare `
  --db "%LOCALAPPDATA%\ContinuityOS\common_operational_memory_v1.db" `
  --capsule SESSION_CAPSULE.json `
  --spec OPERATIONAL_CONTEXT_SPEC.json `
  --out OPERATIONAL_CONTEXT.json

continuity-context verify `
  --db "%LOCALAPPDATA%\ContinuityOS\common_operational_memory_v1.db" `
  --capsule SESSION_CAPSULE.json `
  --spec OPERATIONAL_CONTEXT_SPEC.json `
  --context OPERATIONAL_CONTEXT.json
```

A non-empty WAL is a hard hold. Coordinate a checkpoint before context export;
do not copy the database into DriveFS and do not bypass the hold.
