# R19 Durable Human Approval Production Binding

R19 closes the integration gap between R17 authenticated Human approval and
R18 durable replay storage. It adds one explicit production entry point that
constructs the R18 SQLite replay guard and delegates to the unchanged R17
verifier.

## Production path

`verify_and_consume_human_approval_production(...)` requires an explicit
`replay_db_path`, and that path must be absolute so replay-store identity cannot drift with process CWD. It creates `SQLiteApprovalReplayGuard` itself and then calls
R17 `verify_and_consume_human_approval(...)` with that guard.

The production function deliberately does **not** accept a `replay_guard`
parameter. A caller therefore cannot select `InMemoryApprovalReplayGuard`
through this production API.

There is no environment-variable lookup, temporary-file default, relative-path acceptance, implicit
`:memory:` database, network backend, or hidden fallback.

## Failure model

Replay database initialization happens before the R17 verifier is called.
Storage initialization, schema drift, journal-mode drift, lock timeout, or
other SQLite failures remain fail-closed through the R18 guard contract.

## Authority boundary

R19 changes replay-state binding only. It does not add a GitHub client, merge
API, subprocess runner, deployment surface, private-key signer, trading path,
wallet access, or capital authority. Successful output is still only the R17
`MERGE_ELIGIBLE` receipt for the exact authenticated candidate.

Final merge handoff must still call R17 `require_merge_eligibility_current`
against current repository/base/head/tree and current Human-approval TTL.

## Deployment boundary

The bundled production binding is for one-host deployments using SQLite file
locking. Multi-node deployments still require an external shared atomic CAS or
uniqueness backend and a separately reviewed production binding. R19 does not
claim SQLite as distributed replay protection.

## Acceptance

R19 tests require the production API to have no replay-guard override and no
implicit or relative replay path, prove persistence across fresh binding instances, prove
storage failure stops before verifier delegation, and statically reject new
network/execution/fallback surfaces. The existing R17 and R18 suites continue
to cover cryptographic approval validation and SQLite race/durability behavior.
