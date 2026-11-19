# Person continuity demo R2 — durable SQLite admission

Work order: `COS_PERSON_CONTINUITY_DURABLE_DEMO_R2`.
Specification: RC. Local synthetic candidate; no production admission.

## Goal and baseline

Wire the existing `cos demo person-continuity` command to the existing
`PersonTwinAdmissionStore`. A new process must recover the actual R3 admission
receipt from Memory SQLite, not receive a preassembled receipt file or recreate
that receipt by promoting the candidate again.

Verified local parent: `8120fb04a592661e07ac26d7a20f21b639b3fa27`.
Parent tree: `fe58c85359aa448aa862c2432737c2a9161f4e25`.
Branch: `agent/person-continuity-durable-demo-r2`.

Exactly three source paths are in scope:

- `continuityos/person_twin_demo.py` (existing demo implementation).
- `tests/test_product_person_continuity.py` (existing product test suite).
- `docs/DEMO_PERSON_CONTINUITY_R2.md` (this new document).

R1 documents/manifests, durable-store implementation/tests, R1–R4 contracts,
R21H, the command dispatcher and CI are not changed. In particular the shared
`_fresh_host_context`, `_EmptyReplayFixture` and `_RecordingModel` helpers retain
compatibility with the existing durable-store tests. No new runtime generation,
second Memory database or production service is introduced.

## Run the candidate

Run these commands only with the candidate checkout/package selected; this slice
does not install or switch the user's existing runtime:

```text
cos demo person-continuity
cos demo person-continuity --json
```

The same existing dispatcher is usable from the candidate checkout:

```text
py -3.11 -c "from continuityos.current_entrypoints import cos_main; raise SystemExit(cos_main(['demo','person-continuity','--json']))"
```

The public terminal names remain `COS_DEMO_PERSON_CONTINUITY_PASS` and
`COS_DEMO_PERSON_CONTINUITY_HOLD`. Structured demo, preparation and worker
reports use version 2 schemas and the R2 work-order name. They are unsigned
integrity records, not identity attestations or owner authorization.

## Process and data flow

The controller owns three bounded direct child processes: PREPARE, A and B.
It generates a fresh synthetic run ID before launching any child. The expected
Person identity is deterministically derived from that externally supplied run
ID and fixed fixture parameters; it is not selected from the database contents.

PREPARE creates only an owned temporary `memory.db`. It writes the current
context and retained old/foreign sentinel records using existing Memory methods,
closes/checkpoints its own writer, and uses the existing durable-store API to
initialize admission tables and admit the current record through the real R3.
It requires confirmed publication and an exact saved receipt readback.
The database is quiescent in DELETE journal mode before reader handoff. This
journal choice concerns only the new temporary demo database.

PREPARE's bounded, exact-shape result contains selectors and digests: run ID,
Memory ID, database hash, publication ID and saved-receipt hash. It cannot contain
the full admission receipt, candidate, source text or a context bundle. The
controller checks this shape before starting A. A/B receive only the owned root,
database digest, role and run ID. Neither A's context nor its ALLOW is input to B.

A/B reopen the same database read-only. The store verifies its persisted candidate,
CURRENT pointer, publication and real R3 receipt. The demo constructs fresh
synthetic ledger, policy, session, request, packet and intent inputs, then passes
the actual read-only store to the existing Person evidence adapter and R21H.
The provider reopens/rechecks the pinned snapshot before each context projection.
The prepared database digest is checked before and after these reads.

There is no admission sidecar, no renamed replacement file, and no receipt body
moved into command arguments or PREPARE stdout. Injecting the old sidecar is an
unexpected root member and causes HOLD. Missing or corrupt durable data never
falls back to the old file path, reseeds Memory or regenerates the R3 receipt.

A uses warm chat; B uses the cold streaming path. Recording model fixtures capture
the actual outgoing prompt. Success requires one generation per worker, the same
current evidence and saved admission receipt, different fresh session/request/
intent bindings, exclusion of old/foreign records, and DENY for EXECUTE.

## Existing containment retained

The public `--db` option remains rejected, and normal Memory database resolution
is not used. Declared current-session effect restrictions still stop this demo
before temporary I/O or child creation. Owned-root/no-link checks, source-pinned
isolated Python bootstrap, both-pipe output limits, child timeout/termination/reap,
and cleanup failure as HOLD are retained.

Each child has the existing maximum 20-second execution budget; captured stdout
and stderr remain bounded at 64 KiB per pipe. These are specific demo budgets, not
universal performance or security thresholds. Cleanup is attempted only for the
owned temporary root after the direct children are confirmed reaped. Nothing in
this change cleans existing databases, WAL/SHM files or unrelated folders.

## Validation and review evidence

Validation records are stored outside the source tree under `evidence`. Successful
qualification must bind the current code/test hashes to the final scoped result,
a separate automated audit and an actual command-entrypoint observation. Earlier
failed runs remain separate historical evidence, never relabeled as success.

The product suite covers real PREPARE/A/B processes and deliberately disables
`PersonTwinAdmissionStore.initialize`, `admit` and R3 promotion in reader children.
It also tests missing/altered schema, incomplete CURRENT/publication/receipt,
wrong identity, changed Memory rows, revoked consent, stale session/request at
initial and final prompt boundaries, sealed-but-invalid reports and receipt-body
injection into PREPARE. Deep structural mutations are tested with a recomputed
outer DB hash, so rejection is not credited solely to the file digest.

Full selected compatibility includes the unchanged durable-store and R1–R4/R21H
suites. A separate deterministic audit checks scope, unchanged shared helper
ASTs and absence of sidecar and reader-write paths. This is automated evidence,
not an independent external human/model source review.

## Limits

All data, consent/time/policy/session inputs and model profiles are synthetic.
The host, Python environment and fixture issuer remain trusted. Hashes and the
run ID do not authenticate a hostile host or database owner. This is not C0,
source-origin or egress authentication, live-model inference, a Portable Twin
Vault restore, hardware power-loss qualification or production pilot admission.

The SQLite receipt proves historical admission; it does not create current READ
or EXECUTE authority. External consent updates and later model delivery are not
made one atomic transaction by this demo. There is no durable model-delivery
replay ledger. Python socket audit observations are not OS packet capture or
containment of arbitrary native code.

No push, PR edit, merge, deployment, Scheduler/TPM/service modification, real
Memory use or live model access is part of this local work order. C0 remains
UNVERIFIED/HOLD; native T11/T12 remain UNEXECUTED; the product remains
NOT_PRODUCTION_ADMITTED, execution_authority=NONE, can_execute=false,
can_trade=false and capital_permission=DENY.

## Final execution record

Final scoped run on Windows / Python 3.11.9 / pytest 9.1.1 / SQLite 3.45.1:
**320 passed, 1 skipped, 0 failures, 0 errors**. All 52 runnable product-demo
cases passed. The one pre-existing real-symlink case was skipped because this
Windows process could not create the link; it is not counted as PASS. Code and
test hashes were unchanged. The audit hook observed no socket events; the
validation temporary root was removed.

A separate invocation of the existing cos_main command entrypoint returned PASS:
three real direct children, Memory reference mem:3, no admission sidecar, the
same stored receipt and actual prompt in A/B, distinct fresh sessions, one warm
chat and one cold streaming call, and verified temporary cleanup. Neither this
invocation nor the tests used a live model or the user Memory database.

Failure history is retained: the first product-only run had 36 PASS, 1 SKIP and
16 setup errors caused by one shared fixture returning WORKER_RESULT_INVALID.
Its complete failed worker report was not retained, so its precise underlying
cause is not established. A targeted guarded A worker and the complete guarded
CWD/PYTHONPATH-isolation fixture then passed on the same runtime bytes. The only
subsequent test edit enriched the failure assertion with worker reports; no gate
or timeout was relaxed and no runtime fix is claimed for that early failure.
The final full scoped run and normal CLI observation above passed. The early
non-reproduced failure remains a reproducibility caveat, not erased evidence.

The local result is Tested / PASS WITH CONDITIONS for the observed synthetic
Windows environment. Sealing additionally requires the separate automated audit
to pass. No Linux, installed-wheel or full-repository CI run is claimed for R2,
and no external independent human/model review was performed.
