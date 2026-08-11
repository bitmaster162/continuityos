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

## What it reads

- the exact existing ContinuityOS memory DB, opened read-only;
- memory count and namespaces;
- continuity doctor checks;
- frontiers and open loops;
- the latest checkpoint and its recorded next action;
- Claude and Cursor MCP configuration for the selected DB;
- canon presence and packaged advocate availability.

## What it does not do

`cos status` does **not**:

- create a missing memory DB;
- migrate or repair a DB;
- write memory;
- modify Claude or Cursor configuration;
- spawn an MCP subprocess;
- make a network request;
- dispatch an agent;
- deploy anything.

If the DB is missing or unreadable, the command returns `COS_STATUS_HOLD` and leaves the path untouched.

## MCP status semantics

The default status is configuration evidence only:

- `CONFIGURED` means at least one managed client has the exact ContinuityOS MCP command and selected DB configured;
- `NOT_CONNECTED` means no managed client currently has that exact configuration;
- `DRIFT` means a ContinuityOS entry exists but points at a different command or DB.

This is deliberately **not** called live MCP health because `cos status` does not start a subprocess merely to render status. `cos connect` performs the live `initialize` verification when applying a managed client configuration.

## Continuity semantics

`Continuity HEALTHY` is the existing `Continuity.doctor()` verdict. `ATTENTION` does not silently rewrite or repair anything; use `--verbose` to see every doctor check.

`Next action` is the `next` field from the latest recorded checkpoint. If there is no checkpoint, it is `—`. The status command never invents a successor action.

## Current-session containment

The normal product command remains behind the existing packaged entrypoint containment. In a verified R64 READ_ONLY current session, `cos status` is held before product code is invoked, exactly like other sibling product surfaces. Use the dedicated current-runtime status for that control-plane context.
