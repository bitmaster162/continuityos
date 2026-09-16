# R23 — Multi-Host Durable Replay / CAS

R23 closes the distributed double-consume gap left intentionally open by R18/R19.
It adds a PostgreSQL-backed replay authority for execution topologies with more
than one host. The existing SQLite replay guard remains explicitly `SINGLE_HOST`.

## Contract

The shared authority exposes atomic `claim_once` semantics backed by a database
primary key on `(namespace, approval_id)` and PostgreSQL `ON CONFLICT DO NOTHING`.
Every claim is bound to:

- exact Human approval ID and nonce;
- canonical approval-envelope SHA-256;
- request receipt ID;
- repository, baseline SHA, candidate SHA, and candidate tree SHA.

A claim returns an immutable receipt with one terminal status:
`CLAIMED`, `ALREADY_CONSUMED`, or `CONFLICT`. Only `CLAIMED` is admissible to
R17. A committed claim remains consumed if the caller crashes afterwards.

## Production topology rule

`verify_and_consume_human_approval_production` is the R19 single-host binding and
rejects `execution_host_count > 1`. Multi-host topology must use
`verify_and_consume_human_approval_production_multi_host` with an explicit
PostgreSQL DSN and namespace. Missing driver, database, schema identity, or CAS
state fails closed. There is no PostgreSQL-to-SQLite or memory fallback.

## Authority boundary

R23 only decides replay ownership. It cannot merge, deploy, execute runtime
actions, trade, access wallets, or grant capital authority.

## Qualification boundary

Local tests exercise concurrent authority instances through a shared
transactional fake and verify the emitted PostgreSQL CAS statements. They do not
constitute live two-host PostgreSQL qualification. Production multi-host status
requires a later test against one shared PostgreSQL service from two independent
hosts/process domains, with exactly one `CLAIMED` result.
