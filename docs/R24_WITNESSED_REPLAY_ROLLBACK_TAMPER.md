# R24 — Witnessed Replay Rollback / Tamper Detection

R24 hardens the R23 multi-host replay authority against database rollback,
snapshot restore, silent row tampering, and unwitnessed direct writes.

## Threat model

R23 proves atomic multi-host claim-once behavior inside one shared PostgreSQL
state. It does not detect a later restoration of that database to an older
valid snapshot. A restored snapshot can make a previously consumed approval
appear unused.

R24 adds an external append-only witness in a separate rollback domain.
If PostgreSQL and the witness can be rolled back together, R24 cannot prove
monotonic history and must not be described as rollback-resistant.

## Protocol

For each namespace R24 maintains:

- PostgreSQL witnessed state: generation plus head_sha256;
- PostgreSQL witnessed journal: one chained record per consumed approval;
- the existing R23 approval claim set;
- an external append-only witness carrying the authoritative record chain.

Each witness record binds the exact approval ID, canonical subject, subject
SHA-256, nonce, approval-envelope digest, previous head, generation, and new
head.

Before every claim R24 performs a full integrity sweep:

1. replay journal generations from genesis and recompute every chained head;
2. require the journal head to equal PostgreSQL witnessed state;
3. require the complete approval claim set to equal the journal bindings;
4. compare PostgreSQL state with the external witness state.

Database-ahead-of-witness, same-generation head mismatch, journal tamper,
claim-row tamper, or direct unwitnessed claims fail closed.

## Crash-safe ordering and recovery

The external witness append is committed before the PostgreSQL claim/journal
transaction. This ordering intentionally makes the witness authoritative.

If the process crashes after witness append but before PostgreSQL commit, the
witness is ahead. On the next initialization or claim, R24 validates the
witness chain and replays missing witnessed records into PostgreSQL. The
approval remains consumed; a crash cannot reopen it.

If PostgreSQL is restored to an older snapshot, the same recovery path rebuilds
the missing suffix from the witness. If PostgreSQL contains state not present
in the witness, R24 fails closed instead of guessing which side is correct.

## Migration boundary

R24 does not silently bless pre-existing R23 claims. If a namespace contains
R23 claims but has no R24 witnessed state, initialization fails with
explicit R23 migration required.

A future bounded migration procedure must create independently reviewed
genesis or migration evidence. Auto-hashing the current database into a new
witness would turn a compromised snapshot into trusted history and is
therefore forbidden.

## Production binding

R23 production entrypoints remain available for historical compatibility but
are rollback-unqualified. R24 adds a separate witnessed multi-host production
entrypoint requiring an explicit external witness object with
witness_scope=EXTERNAL_APPEND_ONLY.

There is no fallback from the witnessed path to ordinary R23 PostgreSQL,
SQLite, or memory.

## Authority boundary

R24 only governs replay ownership and recovery of replay evidence. It does not
merge pull requests, deploy software, execute runtime actions, trade, access
wallets, or grant capital authority.

## Qualification boundary

Current tests use a deterministic transactional PostgreSQL fake plus an
independent append-only witness fake. They cover concurrent claim-once,
database rollback recovery, crash-after-witness-append recovery, database
tamper, direct unwitnessed writes, witness rollback, and witness-record tamper.

This is not live production qualification. Production claims require:

- a real external append-only witness in a rollback domain independent from
  PostgreSQL;
- one shared PostgreSQL service;
- at least two independent execution hosts or process domains;
- injected crash and network-partition tests around witness append and DB commit;
- restore-from-snapshot testing against real PostgreSQL;
- operator recovery evidence.

The current full integrity sweep is O(n) in witnessed claims per claim. That is
an intentional safety-first design for low-volume Human approval replay state,
not a claim of unbounded production scalability.

## External I/O and availability boundary

No witness network call is executed while a PostgreSQL transaction or
FOR UPDATE row lock is held. R24 snapshots and audits PostgreSQL, releases the
critical section, performs witness I/O, then reacquires PostgreSQL state and
requires the snapshot to remain current before applying any witnessed suffix.

The witness CAS is the monotonic serializer across hosts. PostgreSQL is a
recoverable materialization of that witnessed history.

A single external witness is intentionally fail-closed and is therefore an
availability dependency. R24 core does not implement witness transport,
timeouts, retries, replication, metrics, paging, or failover. A production
witness adapter must provide bounded network operations, explicit health and
latency telemetry, durable append/read semantics, and an operator recovery
procedure. High availability or a documented RTO/RPO is required before
calling the witnessed path production-qualified.

Witness rotation is also not automatic. Replacing or re-keying the witness
requires a separately reviewed continuity/migration procedure that preserves
the existing chain; silently starting a fresh witness is forbidden.
