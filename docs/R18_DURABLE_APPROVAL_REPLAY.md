# R18 Durable Human Approval Replay Guard

R18 closes the local durability gap left intentionally open by R17. It adds a
stdlib-only SQLite implementation of R17's `consume_once(approval_id)` contract.

## Scope

`SQLiteApprovalReplayGuard` provides:

- durable replay state across process restarts
- atomic consumption across concurrent processes on one host
- strict `hap_<sha256>` approval-ID validation
- SQLite `WAL` journaling and `synchronous=FULL`
- `BEGIN IMMEDIATE` serialization of competing writers
- primary-key uniqueness as the durable replay invariant
- fail-closed behavior when storage or schema integrity cannot be trusted

The implementation introduces no network client, remote service, private-key
handling, merge execution, deployment, runtime, trading, or capital authority.

## Atomicity model

Each `consume_once` call opens an independent SQLite connection and begins an
immediate write transaction. The first writer inserts the approval ID and
commits. Later writers for the same ID observe the primary-key conflict and
return `False`. If a storage failure occurs, the guard raises instead of
returning `True`.

A crash before commit leaves no durable consumption and allows retry. A crash
after commit may consume an approval before the caller receives the return
value; that is a liveness loss, not an authority escalation, and requires a new
Human approval.

## Deployment boundary

R18 is a one-host durable baseline. SQLite file locking is not a distributed
consensus protocol. Multi-node deployments must provide a shared durable CAS
implementation of the same `consume_once` contract and must not claim R18's
SQLite guard as cross-node replay protection.

## Production binding

R18 intentionally defines storage semantics only. R19 binds the authenticated
R17 approval verifier to `SQLiteApprovalReplayGuard` through an explicit
operator-provided file path. The R19 production API does not accept a caller-
supplied replay guard and therefore cannot silently fall back to the R17
in-memory test/dev primitive.
