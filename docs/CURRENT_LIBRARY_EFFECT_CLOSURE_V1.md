# Current Library Effect Closure v1 (R28)

R28 extends the R27 lazy direct-surface guard to residual public library APIs that can still perform product effects without passing through the contained CLI or Store boundaries.

## Guarded effects

When a current session is declared, these public effects fail closed before the effect occurs:

- updater outbound version check/cache write and `git`/`pip` self-update execution;
- rules export filesystem writes (`dry_run=True` remains available);
- historical operational-context `prepare` output creation (`build`/`verify` remain read-only);
- historical session-input `prepare` output creation (`build`/`verify` remain read-only);
- setup wizard and dashboard generation;
- Sim-OS `run_loop` / module execution;
- fork snapshot creation and merge-back mutation;
- centralized ledger server start;
- centralized ledger write-capability token issuance;
- `LedgerSink.record()` and `LedgerSink.flush()` network / durable-buffer effects.

The existing R27 protections for direct OperationalMemory, historical gate engine/ledger and MCP remain unchanged.

## Module execution

`python -m continuityos.sim.loop` is held for any declared current session.

Historical R63 context/session modules are selective: `prepare` is held because it creates output, while `verify` is not blanket-blocked by the import guard.

## Compatibility

No current binding means legacy/product behavior is delegated unchanged. Importing top-level `continuityos` still does not eagerly import any guarded target module.

The historical/product implementation modules are not edited by R28. Containment is applied lazily after import through the same stdlib meta-path boundary introduced by R27.

## Non-claims

R28 does not make arbitrary Python or OS calls impossible; code outside the ContinuityOS public API can always invoke the operating system directly. The closure is scoped to ContinuityOS public effect surfaces.

R28 does not deploy, apply current state, mutate Control Center/R64 or Drive, dispatch agents, send external messages, trade, access wallets, or grant capital permission.

`can_trade=false`, `capital_permission=DENY`, and `deploy_permission=DENY` remain unchanged.
