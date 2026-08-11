# `cos status`

`cos status` is the read-only product health surface for ContinuityOS.

It is intentionally separate from the R64/current-runtime control-plane status. The command answers the questions a normal product user needs without creating memory, changing client configuration, starting servers, or probing the network.

## Quick use

```bash
cos status
cos status --verbose
cos status --json
cos --db /path/to/memory.db status --json
```

Example shape:

```text
ContinuityOS status  READY
Memory      READY  18420 memories  /home/user/.continuityos/memory.db
Continuity  HEALTHY  8/8 checks
Last state  14m ago  checkpoint #18421
Open loops  2
Next action Ship the next product increment
Agents      Claude CONNECTED | Cursor NOT_CONNECTED
MCP         CONFIGURED  (config only; no live probe)
Governance  ARMED  6 canon item(s)
```

## Zero-write snapshot contract

The selected memory DB is read through SQLite `immutable=1`, not through a normal writable or WAL-participating connection. Before and after the snapshot, `cos status` checks for non-empty `-wal` or rollback-journal sidecars and verifies that the main DB size/mtime did not change during the read.

If the database is actively changing or has a non-empty sidecar, status returns:

```text
COS_STATUS_HOLD
reason = MEMORY_DB_NOT_QUIESCENT
```

It does not ignore active WAL state and it does not perform recovery or checkpointing merely to obtain a status view.

## What it reads

- the exact existing ContinuityOS memory DB from one quiescent immutable snapshot;
- memory count and namespaces;
- the same continuity-doctor invariants from that snapshot;
- frontiers and open loops;
- the latest checkpoint and its recorded next action;
- Claude and Cursor MCP configuration for the selected DB;
- canon presence and packaged advocate availability.

## What it does not do

`cos status` does **not**:

- create a missing memory DB;
- migrate, checkpoint, recover, or repair a DB;
- write memory;
- create SQLite sidecars as part of the status snapshot;
- modify Claude or Cursor configuration;
- spawn an MCP subprocess;
- make a network request;
- dispatch an agent;
- deploy anything.

If the DB is missing or unreadable, the command returns `COS_STATUS_HOLD` and leaves the path untouched. If it is non-quiescent, it returns HOLD rather than reporting a potentially stale immutable view.

## MCP status semantics

The default status is configuration evidence only:

- `CONFIGURED` means at least one managed client has the exact ContinuityOS MCP command and selected DB configured;
- `NOT_CONNECTED` means no managed client currently has that exact configuration;
- `DRIFT` means a ContinuityOS entry exists but points at a different command or DB.

This is deliberately **not** called live MCP health because `cos status` does not start a subprocess merely to render status. `cos connect` performs the live `initialize` verification when applying a managed client configuration.

## Continuity semantics

`Continuity HEALTHY` uses the same invariants as the existing `Continuity.doctor()` surface, evaluated from the immutable snapshot. `ATTENTION` does not silently rewrite or repair anything; use `--verbose` to see every check.

`Next action` is the `next` field from the latest recorded checkpoint. If there is no checkpoint, it is `—`. The status command never invents a successor action.

## Current-session containment

The normal product command remains behind the existing packaged entrypoint containment. In a verified R64 READ_ONLY current session, `cos status` is held before product code is invoked, exactly like other sibling product surfaces. Use the dedicated current-runtime status for that control-plane context.
