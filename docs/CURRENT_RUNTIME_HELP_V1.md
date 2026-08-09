# Current Runtime Help v1 (R31)

`continuity --help` now preserves the historical ContinuityOS help output and appends a small **Current runtime** discovery section.

The added section makes the merged current-session operator surface discoverable without changing historical command parsers or nested command help. It lists:

- `current-status` — inspect the declared current-session binding and effective ceilings;
- `preflight` — read-only assessment; a verified current session never grants execution;
- `run` — held when a current session is bound;
- the four environment variables used to declare/require a current session.

## Compatibility

Only top-level `continuity --help` and `continuity -h` are augmented. The supported global `--db` prefix also preserves this behavior.

Nested help such as `continuity cold-start verify --help` remains owned by the existing safe/historical dispatch path and is not modified.

The help path does not verify a challenge, inspect an ACK, evaluate policy, open a ledger, execute a command, mutate state, deploy, dispatch agents, trade, access wallets, or send external messages.

`can_trade=false`, `capital_permission=DENY`, and `deploy_permission=DENY` remain unchanged.
