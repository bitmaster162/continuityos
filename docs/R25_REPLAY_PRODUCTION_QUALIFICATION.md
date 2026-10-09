# R25 — Replay Production Qualification Harness

R25 qualifies the R24 witnessed multi-host replay protocol against a real
PostgreSQL server and an external durable witness process instead of relying
only on deterministic fake backends.

R25 is a qualification and hardening increment. It does not add merge,
deployment, runtime-execution, trading, wallet, or capital authority.

## Baseline

R25 starts from master
57c90dd4c7f8ec2a47a9d8b8a48e7d9fb1a11eaa.

That baseline already includes:

- R23 durable multi-host PostgreSQL CAS;
- R24 external witnessed rollback/tamper protection;
- Remote Commander PRs #197, #198, and #200.

The Remote Commander files are disjoint from the replay qualification files.

## Real qualification environment

The local qualification harness uses:

- Docker Engine 29.7.2;
- PostgreSQL 17-alpine in a dedicated container and named volume;
- psycopg 3.3.6 through the project multi-host-replay optional dependency;
- a separate Python 3.13 Alpine witness container and separate named volume;
- host ports published only on 127.0.0.1;
- at least two independent worker subprocesses.

The witness fixture persists canonical JSONL records and fsyncs each append
before acknowledging it. It implements compare-and-set against exact
generation and head SHA-256. On startup it revalidates each stored record's
schema, namespace, generation sequence, previous-head link, subject hash,
record hash, and record ID before admitting the log into memory. A deterministic post-fsync barrier allows the
controller to kill a worker in the crash window after witness durability but
before PostgreSQL reconciliation.

The witness fixture is intentionally not a production witness service. It is
loopback HTTP without authentication or TLS and reports production_ready=false.

## Fault matrix

A green R25 local-container receipt requires all of these cases:

1. Concurrent double claim
   - eight independent workers consume the same approval concurrently;
   - exactly one returns CLAIMED;
   - exactly seven return ALREADY_CONSUMED;
   - PostgreSQL contains one claim and one witnessed generation.

2. PostgreSQL snapshot rollback
   - capture a real pg_dump before the claim;
   - consume the approval;
   - restore PostgreSQL to the pre-claim database snapshot;
   - the next claim rebuilds the missing suffix from the external witness;
   - the result is ALREADY_CONSUMED, never a reopened capability.

3. Crash after durable witness append
   - the witness fsyncs the claim;
   - the witness signals the deterministic post-append barrier;
   - the controller kills the worker before PostgreSQL reconciliation;
   - PostgreSQL still shows generation zero before recovery;
   - the next worker reconstructs the claim and returns ALREADY_CONSUMED.

4. Witness outage
   - stop the witness container;
   - replay authority fails closed;
   - there is no fallback to ordinary PostgreSQL, SQLite, or memory;
   - after witness recovery a fresh claim can proceed.

5. PostgreSQL outage
   - stop the PostgreSQL container;
   - replay authority fails closed with a bounded PostgreSQL connection error;
   - after PostgreSQL recovery a fresh claim can proceed.

6. Witness rollback
   - capture witness bytes before a claim;
   - consume the approval so PostgreSQL advances;
   - stop the witness and restore its old log bytes;
   - restart the witness;
   - synchronize fails closed because the database is ahead of the witness.

7. PostgreSQL row tamper
   - consume an approval;
   - directly alter its stored digest in PostgreSQL;
   - synchronize fails closed on the claim-set integrity audit.

## R25 finding: real SERIALIZABLE contention

The first real-PostgreSQL concurrency run exposed a production-hardening gap
that deterministic fake tests did not reproduce.

With two concurrent workers, PostgreSQL SERIALIZABLE could abort one
reconciliation transaction. No double spend occurred: the other worker
recovered the witnessed claim and returned ALREADY_CONSUMED. However, the
desired response invariant of one CLAIMED plus one ALREADY_CONSUMED was not
met because the aborted transaction was surfaced as a generic fail-closed
synchronization error.

R25 hardens witnessed replay with bounded retries for PostgreSQL SQLSTATE:

- 40001 — serialization_failure;
- 40P01 — deadlock_detected.

Only those retryable transaction failures are retried. Witness errors,
integrity errors, tamper evidence, connection failures, and all unknown
database failures remain fail-closed.

The existing eight-attempt contention bound remains the outer limit. Exhaustion
still returns a replay contention error rather than widening authority.

## Qualification status

A successful harness run returns:

LOCAL_CONTAINER_QUALIFICATION_GREEN

This does **not** mean production_qualified_multi_host=true.

The receipt must explicitly keep production_qualified_multi_host=false because:

- PostgreSQL, witness, and workers still share one physical laptop;
- the qualification witness transport is unauthenticated loopback HTTP;
- service-stop tests are not packet-level network partitions;
- host-level rollback could correlate the two Docker named volumes.

## Required next qualification

A future promotion to real multi-host production qualification requires:

- an independently administered witness in a different physical or failure
  domain;
- at least two physical hosts or independent VMs for execution workers;
- authenticated and encrypted witness transport;
- packet-level partition and asymmetric network-fault injection;
- real operator witness rotation and recovery drill;
- explicit RTO/RPO and witness availability evidence.

## Running locally

The qualification must run from a clean R25 candidate for final evidence.

On Windows, Docker Desktop launched through Remote Commander may need the
standard ProgramData environment value restored before starting Docker:

    ProgramData=C:\ProgramData

The harness itself uses only ephemeral loopback ports, dynamically named
containers, and dynamically named Docker volumes. Unless --keep is supplied,
it removes its qualification containers and volumes in a finally block.

The receipt is written outside the repository so producing evidence does not
mutate the candidate Git tree.
