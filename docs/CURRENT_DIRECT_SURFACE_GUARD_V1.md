# Current Direct Surface Guard v1 (R27)

R27 closes the direct Python/module bypasses explicitly left open by R26 without rewriting the historical implementation modules.

## Scope

Guarded direct surfaces:

- `continuityos.operational_memory.OperationalMemory`
- `continuityos.gate.engine.preflight`
- `continuityos.gate.ledger.Ledger`
- `continuityos.mcp_server` service lifecycle

The package installs one narrow stdlib meta-path watcher at `import continuityos`. The watcher does not import any guarded target. When a target is later imported, its dangerous surface is wrapped while its historical implementation remains unchanged.

## Current-session behavior

A declared current session must pass the exact R23/R64 challenge + controller-pinned challenge SHA-256 + BOOT_ACK verification already owned by `current_effect_boundary`.

For a verified current session:

- direct `OperationalMemory` construction is forced read-only before directory, SQLite, WAL, or schema-creation effects;
- every operational-memory write transaction re-checks the boundary, including objects created before the binding appeared;
- direct historical `gate.engine.preflight` returns the same pure HOLD receipt before policy evaluation or ledger append;
- direct historical `gate.ledger.Ledger` may read an existing ledger but never creates one or appends;
- direct MCP `Server()` and `main()` are held before memory/service initialization;
- `python -m continuityos.operational_memory` and `python -m continuityos.mcp_server` fail closed when a current/partial binding is declared.

A partial or invalid current binding is REVISE and never falls back to legacy behavior.

## Legacy compatibility

With no current-session binding, wrappers delegate to the historical implementations. The target modules remain lazily loaded; importing top-level `continuityos` does not import operational memory, gate engine/ledger, or MCP.

## Non-claims

R27 does not grant execution or write authority and does not canonicalize anything. It does not mutate Control Center/R64, Drive, current state, deployment state, wallets, trading permissions, or capital permission.

`can_trade=false` and `capital_permission=DENY` remain unchanged.

R27 is a containment layer, not an authority promotion.
