# Current Runtime Monotonic Clamp v1

R23 fixes fresh-session authority binding. R24 closes the next boundary: after a correct current cold-start, ordinary `continuity preflight/run` must not silently fall back into the legacy local policy + memory DB + ledger execution plane.

## Principle

A verified current cold-start challenge is **context evidence, not an execution grant**.

Current authority is monotonic with respect to legacy policy: it may make a legacy decision stricter, but it cannot turn a denial/hold/absence of authority into permission to execute.

For the current R64 contour, R23 admits only exact ACTIVE pointer/root state with:

- `NO_FURTHER_AGENT_WORK=true`;
- `effect_ceiling=READ_ONLY` for the current session;
- `auto_dispatch=false`;
- `can_trade=false`;
- `capital_permission=DENY`;
- `deploy_permission=DENY`.

Therefore R24 does **not** create a current execution engine. A bound current `run` is held before legacy policy, ledger, rollback materialization, or subprocess execution.

## Binding

A process opts into current runtime binding with all three environment variables:

```text
CONTINUITYOS_CURRENT_CHALLENGE=<path to CURRENT_COLD_START_CHALLENGE.json>
CONTINUITYOS_CURRENT_CHALLENGE_SHA256=<controller-pinned challenge SHA-256>
CONTINUITYOS_CURRENT_ACK=<path to verified BOOT_ACK.json>
```

Optional:

```text
CONTINUITYOS_CURRENT_SESSION_REQUIRED=1
```

When `CURRENT_SESSION_REQUIRED` is true, missing binding inputs fail closed.

If any one of the three binding variables is present, the process is treated as intending current mode. A partial binding is an error; it never falls back silently to legacy runtime.

## `continuity preflight`

With a complete current binding, `preflight` verifies the exact R23 challenge + pinned SHA + ACK and emits a pure current-runtime receipt.

The preflight operation itself may PASS as a read-only analysis, but its execution decision remains `HOLD`. It does not call the legacy engine and does not append to the legacy ledger.

## `continuity run`

With a complete current binding, `run` verifies the same exact session and returns `CURRENT_RUNTIME_RUN_HOLD` before:

- legacy policy evaluation;
- local memory DB context evaluation;
- ledger append;
- rollback snapshot creation;
- subprocess execution.

This prevents a valid current cold-start from degrading into legacy execution semantics on the next command.

## Compatibility

When no current-session binding is declared and `CONTINUITYOS_CURRENT_SESSION_REQUIRED` is false/unset, R24 delegates unchanged to the R23 safe CLI. This preserves the general open-source/legacy runtime rather than globally imposing Robert's current R64 control state on unrelated installations.

Cold-start prepare/verify and all other commands continue through the R23 safe CLI; R24 intercepts only `preflight` and `run` when current runtime binding is active.
