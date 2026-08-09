# Current Entrypoint Containment v1

R24 clamps `continuity preflight/run` after a verified current R64 cold-start. The installed package also exposes sibling entrypoints that historically predate the current-authority runtime boundary:

- `cos`
- `continuity-state`
- `continuity-memory`
- `continuity-context`
- `continuity-session`

Without containment, a process that has already declared a current session could call one of those sibling scripts and silently fall back into legacy/product behavior outside the verified current-session clamp.

## Rule

No current-session binding means no behavior change. All historical/product entrypoints delegate exactly as before.

Once any current-session binding is declared through the R24 environment variables, the binding must be complete and must verify against the exact R23 current cold-start challenge + controller-pinned challenge SHA-256 + BOOT_ACK.

For the present R64 contour, the verified session is `READ_ONLY` and the authority pointer carries `NO_FURTHER_AGENT_WORK=true`. Therefore sibling entrypoints fail closed before legacy implementation import/call.

The sole allowed sibling operation is:

`continuity-state evaluate --input <bundle.json>`

That operation is already pure/read-only and performs only deterministic state/evidence resolution.

## Specifically blocked in current mode

`cos` is blocked before memory writes, rules export, setup/sim, MCP/API servers, message-bus servers, usage mutation, self-update or any other product action.

`continuity-memory` is blocked before opening a mutable operational-memory path or appending events/claims/decisions/checkpoints.

`continuity-context` and `continuity-session` are blocked because their current schemas are historical R63-bound context/session-input formats and must not masquerade as current R64 session context.

`continuity-state prepare-cold-start` is blocked because it is the historical state-bound R63 preparer. Current preparation belongs to `continuity cold-start prepare`, which is bound to the exact ACTIVE current pointer and its stable roots.

## Fail-closed binding

Partial current-session environment binding never falls back to legacy behavior. Invalid challenge/ACK verification also fails closed.

This patch does not deploy, mutate Control Center/R64, apply current state, activate memory, dispatch agents, trade, grant capital permission, or authorize execution.
