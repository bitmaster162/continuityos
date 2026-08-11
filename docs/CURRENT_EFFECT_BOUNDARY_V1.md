# Current Effect Boundary v1

R24 clamps the installed `continuity preflight/run` runtime path and R25 contains sibling console entrypoints. Those layers are necessary but not sufficient for a Python package: a caller can import storage, governance, HTTP, or bus modules directly.

R26 adds a lower monotonic boundary for the verified current R64 session. A current cold-start challenge proves context; it is not a write, execution, network, or deployment grant.

## Binding rule

With no current-session environment binding, legacy/product behavior is unchanged.

If any current-session binding is declared, it must contain the exact challenge path, controller-pinned challenge SHA-256, and BOOT_ACK and must pass current-runtime verification. Partial or invalid binding fails closed and never falls back to legacy behavior.

For the current contour, a verified binding means:

- authority generation `R64`
- session effect ceiling `READ_ONLY`
- authority ceiling `NO_FURTHER_AGENT_WORK`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Protected surfaces

### Core Store

`Store` is forced into SQLite read-only mode for a verified current session. `add`, `_add_locked`, `update_meta`, and `delete` re-check the boundary at call time, so an object created before the binding appeared cannot later be used as a stale writable handle.

This also constrains ordinary `Memory.remember`, `Memory.upsert`, `Memory.write_checked`, `Memory.supersede`, and `Memory.forget`, because they persist through `Store`.

### Public gate

The public `continuityos.gate.preflight` name routes through a current adapter. In current mode it returns a pure `HOLD` receipt before legacy policy evaluation and before any ledger append.

The public `continuityos.gate.Ledger` name opens an existing ledger read-only in current mode. It never creates a missing ledger or appends to an existing one.

### HTTP API

HTTP GET/read surfaces remain read-only. HTTP POST is held before body-driven mutation. Starting the HTTP API service itself is held in current mode.

### Message bus

Read-scoped token minting remains pure. Write-scoped token minting, `memory.upsert`, `memory.remember`, and bus server start are held in current mode.

## Explicit residual surfaces

R26 does **not** claim that every internal module has been converted into a current-aware API.

Two residual internal surfaces remain for the next bounded review:

1. direct use of `continuityos.operational_memory.OperationalMemory` and its internal append/write transactions;
2. direct import of historical `continuityos.gate.engine.preflight` / `continuityos.gate.ledger.Ledger`, which remain compatibility/testing modules behind the current-safe public gate names.

Direct MCP server startup is also not treated as an execution grant by R26. Its normal memory mutations pass through the guarded core Store and its normal gate imports resolve to the current-safe public gate, but its service lifecycle and any non-Store side effects remain part of the next service-boundary audit.

R26 does not deploy, mutate Control Center/R64, apply current state, activate memory, dispatch agents, trade, access wallets, grant capital permission, or authorize execution.
