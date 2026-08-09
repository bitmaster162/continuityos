# State-Bound Cold Start v1

`continuity-state prepare-cold-start` closes the stale-state gap between evidence
reconciliation and ANTI_AMNESIA cold-start preparation.

Flow:

1. Load one bounded `continuityos.state_resolution.bundle/v1`.
2. Resolve authority/evidence with the R18 state-resolution guard.
3. Require both `STATE_RESOLUTION_PASS` and a selected current status of exactly
   `PASS` or `PASS_WITH_CONDITIONS`.
4. Only then call the existing cold-start challenge preparer.
5. Return a receipt binding the state-bundle SHA-256, canonical resolution SHA-256,
   selected artifact identity, operational qualification, and cold-start receipt.

The command fails closed before cold-start writes when the selected state is
`OPEN`, `PARTIAL`, `HOLD`, `REJECT`, or `REVISE`, or when a fresh current provider/audit
contradiction causes the resolver to HOLD.

`PASS_WITH_CONDITIONS` remains operational acceptance only; it never becomes
`production_qualified=true` merely because cold-start preparation is allowed.

This path does not mutate Control Center current state, R64, registries, deployment,
trading, wallets, capital permissions, memory activation, or external messaging.
The existing legacy cold-start v1 remains byte/schema compatible; this command is
a guarded entry point around it rather than a rewrite of historical R63-bound bytes.
