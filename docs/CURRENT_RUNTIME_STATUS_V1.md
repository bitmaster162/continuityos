# Current Runtime Status v1 (R30)

`continuity current-status` is a pure read-only operator view over the installed current-session runtime binding.

It answers one question without requiring the operator to manually inspect environment variables, challenge files, ACK receipts, or legacy policy state: **what runtime authority is this process actually bound to right now?**

## Outcomes

### `CURRENT_RUNTIME_STATUS_UNBOUND`

No current-session binding was declared. The command reports `mode=LEGACY_UNBOUND`. It does not execute or delegate a legacy command.

### `CURRENT_RUNTIME_STATUS_REVISE`

A current session was declared but the binding is incomplete, invalid, or the cold-start ACK does not verify. Legacy fallback is false and execution remains HOLD.

### `CURRENT_RUNTIME_STATUS_PASS`

The exact current challenge, controller-pinned challenge SHA-256, and BOOT_ACK verify. The receipt exposes:

- authority generation;
- challenge id;
- challenge SHA-256;
- ACK SHA-256;
- binding input paths;
- `session_effect_ceiling=READ_ONLY`;
- `authority_ceiling=NO_FURTHER_AGENT_WORK`;
- `execution_decision=HOLD`;
- a compact capability view showing read-only inspection/preflight availability and effectful execution HOLD.

## Safety properties

`current-status` never evaluates legacy policy, writes a ledger, executes a command, mutates current state, deploys, dispatches agents, trades, accesses wallets, or sends external messages.

It is an observability surface only. A PASS means the current context binding is verified; it is not an execution grant.

`can_trade=false`, `capital_permission=DENY`, and `deploy_permission=DENY` remain unchanged.
