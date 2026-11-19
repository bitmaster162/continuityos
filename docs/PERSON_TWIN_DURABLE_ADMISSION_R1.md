# Person Twin durable admission — R1 local candidate

Work order: `COS_PERSON_TWIN_DURABLE_ADMISSION_R1`.

Implementation: **Tested in the bounded synthetic Windows environment described below**.
Review conclusion: **PASS WITH CONDITIONS for a local candidate**, not production admission.
Independent external human/model source review: **NOT PERFORMED**. Author review and a
separate deterministic audit process are identified explicitly; they are not independent agents.

## Purpose and exact scope

Persist the admission evidence required by the existing R4/R21H read path across a
process boundary without manufacturing a replacement R3 receipt at read time.
The ordinary Memory database remains the single SQLite file. An explicit store
adapter adds its own tables; it does not create a second memory database or modify
`items`, the existing R3 coordinator, R4 evaluator, Person evidence adapter, R21H,
CLI, MCP, or the earlier continuity demo.

Exactly three new repository files:

- `continuityos/person_twin_admission_store.py`
- `tests/test_person_twin_admission_store.py`
- `docs/PERSON_TWIN_DURABLE_ADMISSION_R1.md`

The existing `cos demo person-continuity` command remains unchanged and still uses
its original fixture sidecar. This slice proves the new durable path through a
separate synthetic test harness; it does **not** switch that command to the store.

## Baseline recovery

The former local demo commit `fa642ba9b81c926d78a0d61dd4169d57b90ed65e` was
unavailable. The owner separately approved replacing it with a new recovery commit
only after proving full-tree identity.

Verified public parent: `28bfce3c1900d11bcc90fdd9428295ce18c68b14`.
Parent tree: `fcb37ef8d9af2c349a62c576b5634798881a7fbe`.
Original supplied patch SHA-256:
`56867bd83c9e8ff4d15e93f81e020d02448fa91a2eff1d96c2589d2e65a0ab3e`.

The patch applied cleanly to a fresh, full checkout. `git write-tree` reproduced
`b989e36d3703b0a6dd8b5edd60ea50367c864f1e` exactly, including all unchanged files.
New recovery commit: `3b166d4beacc1a81f17ee07e2a042f192914e326`.
This is a different commit with the same approved source tree, not the missing
original object. Git history is shallow at the verified public parent; checkout
contents are complete. Initial `git fsck --full` and clean-worktree checks passed.

The local implementation branch is `agent/person-durable-admission-r1`. Work is
kept in a new isolated directory on the authorized owner workstation, not in the
older shared worktrees. No GitHub write, PR edit, merge, deployment, service,
Scheduler, TPM, credential, trading, or real-memory operation is part of this slice.

## Storage and transaction contract

`PersonTwinAdmissionStore` opens an explicitly supplied existing Memory database.
The constructor is read-only by default. Missing files or admission schemas are
errors; read-only opening never creates the database or admission schema.
`initialize(path)` is a separate explicit schema-write operation on an existing
Memory database. Initialization is idempotent only for the exact supported schema;
partial, altered or unexpected schemas are not silently repaired or migrated.

The adapter owns a separate SQLite connection. Writers use explicit transactions,
`foreign_keys=ON`, `trusted_schema=OFF`, and `synchronous=FULL`; readers use
`query_only=ON`. These relevant settings and the exact schema are rechecked at
write boundaries. The existing database journal mode is not changed. Each store
instance belongs to one thread; independent writers open independent instances.

The schema has four tables:

1. A version marker.
2. Scoped candidate bytes, historical source/consent/identity anchors, and exact
   Memory row binding, each with an integrity hash.
3. Append-only-by-API publications containing the actual R3 CURRENT receipt,
   pointer, candidate binding and previous-publication identity.
4. One CURRENT pointer per tenant/twin identity fingerprint.

Candidate staging is committed separately as non-current. Only the configured
`admit()` sequence enables the existing R3 storage callbacks. Direct candidate
writes and pointer promotion through those callbacks are rejected otherwise.

R3 performs its unchanged state transitions:

`STAGED -> VALIDATED -> COMMITTED_NOT_CURRENT -> POSTVERIFY_PASS -> CURRENT`.

Before promotion, `BEGIN IMMEDIATE` acquires the writer transaction. The expected
publication identity and R3 pointer SHA are checked. R3 writes its pointer into
this transaction and produces its real final receipt. The adapter then inserts
that exact receipt and its linked publication before the single promotion COMMIT.
A deferred composite foreign key rejects COMMIT of a CURRENT pointer that has no
matching publication/receipt row. Candidate identity cannot be rebound to another
Memory ID or namespace, even if its text is identical.

The transaction is verified before commit with the existing R4 structural
admission validator. After COMMIT, a **new read-only connection** reads and checks
the whole snapshot. Success requires exact equality with the committed candidate,
pointer, receipt, anchors and binding. A concurrent change in the intervening
window gives HOLD, not a stale success or automatic retry.

Reference semantics: SQLite explicit transactions and deferred constraints are
specified in https://www.sqlite.org/lang_transaction.html and
https://www.sqlite.org/foreignkeys.html. Python explicit transaction handling is
described in https://docs.python.org/3.11/library/sqlite3.html. This implementation's
observed results are the tests below, not a blanket claim about every deployment.

## Results and uncertain writes

The operation reports separate candidate and promotion commit states:
`NOT_ATTEMPTED`, `UNKNOWN`, or `CONFIRMED`.

- PASS requires confirmed promotion plus fresh readback verification.
- A lost candidate COMMIT acknowledgement returns HOLD with
  `CANDIDATE_COMMIT_OUTCOME_UNKNOWN`, `candidate_persisted=null`, and
  `possible_persisted_effect=true`.
- A lost promotion COMMIT acknowledgement returns HOLD with
  `COMMIT_OUTCOME_UNKNOWN`. A new reader may subsequently find a complete saved
  bundle; the original caller must not infer that no write happened.
- Confirmed commit followed by failed readback returns
  `POSTCOMMIT_READBACK_FAILED`; it is not described as rollback.
- Failed rollback returns `ROLLBACK_UNVERIFIED`, marks a possible effect, suppresses
  the successful receipt, and suspends/closes that connection.

There is no automatic replay after uncertainty. A staged candidate may remain
when later validation fails. Initialization exceptions also must not be interpreted
as proof of an unchanged file after an uncertain commit. No compensating deletion
or implicit repair is performed.

## Read contract and authority boundary

`load_current()` verifies the persisted snapshot in a read transaction. Immutable
snapshot bytes and separately decoded dictionaries prevent accidental mutation of
previously returned bytes. Existing R3/R4 readback methods read actual SQLite data,
not a cached ALLOW. Candidate/current lookup is bound to the supplied tenant, twin
and identity fingerprint.

A saved receipt is **historical admission evidence**, not current authorization.
The reader must still obtain fresh independently trusted time, revocation/consent,
policy, principal, session, request and intent bindings. The test harness combines
the saved bundle with newly generated synthetic host/session inputs and the
unchanged R4/R21H evaluator. No SQL column supplies a new grant.

All operation results retain:

```text
production_admission_status=NOT_PRODUCTION_ADMITTED
execution_authority=NONE
can_execute=false
can_trade=false
capital_permission=DENY
```

Current-session effect checks are reused on every public write boundary and
material commit boundary. The adapter does not bypass an active declared current
mode. In the lab with no such declaration, the trusted host is responsible for the
explicit owner-approved operation. This API is not an independently authenticated
owner signer or a production authorization service.

## API shape

This fragment documents the API, not runnable authority or real-data permission:

```python
# path must be an explicitly approved existing synthetic Memory database.
PersonTwinAdmissionStore.initialize(path)
with PersonTwinAdmissionStore(path, identity=identity, read_only=False) as writer:
    result = writer.admit(
        consent_receipt=consent_receipt,
        source_record=source_record,
        candidate_record=candidate_record,
        purpose="person-memory",
        memory_id=memory_id,
        namespace=namespace,
        read_current_evidence=read_fresh_ledger_and_time,
    )
# A new process supplies the controller's expected identity again.
with PersonTwinAdmissionStore(path, identity=identity) as reader:
    snapshot = reader.load_current()
# Still run fresh R4/R21H authorization before disclosing snapshot contents.
```

`read_fresh_ledger_and_time()` must return exactly
`{"current_revocation_ledger": ..., "at": ...}`. A missing/extra field, invalid time
or revoked/expired evidence is rejected. The 1 MiB record limit and bounded
connection timeout are lab limits, not calibrated universal production thresholds.

## Executed validation

Executed on 2026-10-13 on Windows, Python **3.11.9**, pytest **9.1.1**, SQLite
**3.45.1**. Source and tests remained hash-identical throughout the final run.

Final scoped selection, importlib mode: **294 passed, 1 skipped, 0 failures,
0 errors**. All **52 new durable-admission cases passed**. The single skipped
pre-existing demo case requires a real filesystem symlink that this Windows
process could not create. It is not counted as a passed link-isolation test.

Selected files:

```text
tests/test_person_twin_admission_store.py
tests/test_person_twin_admission_contracts.py
tests/test_person_twin_privacy_provenance.py
tests/test_person_twin_admission_coordinator.py
tests/test_person_twin_authority_replay.py
tests/test_person_twin_r21h_evidence.py
tests/test_product_person_continuity.py
```

The final runner denied every `socket.*` Python audit event; zero occurred in its
process. Explicit spawned durable-test workers independently install that guard;
the existing demo workers retain their own guard. This is not OS packet capture
or an isolation claim against arbitrary native code.

Coverage includes actual A/B process separation, receipt equality, fresh session
inequality, real R4 decisions, actual captured R21H prompt JSON, exactly one model
call per worker, and exclusion of old/foreign records. Process B receives only
the DB path and expected identity, not a serialized admission sidecar. R3 promotion
is made to fail if invoked in B, establishing that the reader did not regenerate
the receipt. The model is a recording fixture, not live inference.

Two real competing writer processes produce one winner. Separate real processes
exit at code 73 after the transactional pointer write or immediately before COMMIT;
the old complete publication survives. Fault injection also tests commit
acknowledgement loss, failed postcommit reopen, unverified rollback, lock contention,
reentry, wrong identity/scope/Memory binding, changed consent/session/request,
corrupt bytes/schema, and disabled foreign-key enforcement.

## Review and retained failure history

The author's initial run was 36 PASS / 2 FAIL. One failure identified a real
candidate-commit uncertainty reporting defect: the write could persist while
`possible_persisted_effect` was false. Separate tri-state tracking corrected it.
The other failure was a test assertion against raw multiline text embedded in JSON;
the test now decodes and checks the actual evidence payload. The repaired initial
38-case suite passed, then 14 further boundary cases were added.

Several validation-recorder attempts failed without changing source semantics.
One called `platform.platform()`, which invokes a local hostname socket audit event
on Windows and was correctly denied. Another gave pytest a missing parent folder;
a later custom temp root was outside the OS temporary directory required by the
unchanged demo and caused expected root/cleanup rejection. The final recorder uses
`sys.platform`, an existing OS-temp parent, a new dedicated temp directory, and the
same complete seven-file test selection. Earlier logs are retained, not relabeled.

A separate Python process performed a deterministic AST/import/effect-label/Git
check and independently exercised the extracted DDL in an in-memory SQLite DB.
It confirmed that committing a pointer without its receipt is rejected and rollback
restores the empty pointer table. This audit passed on the exact current module and
test hashes. It is additional automated evidence, **not** an independent human or
model review of all source semantics.

## Remaining limits and next boundary

The host and controller identity inputs remain trusted. Hashes do not authenticate
a hostile DB owner; full-file rollback, malicious coordinated SQL/hash rewrites,
key custody, trusted monotonic time, source origin, broker/client identity and
egress consent remain separate problems. File identity and no-link checks narrow
ordinary path mistakes; they do not prove race-free native handle custody.

Process exits tested here are not hardware power-loss, disk-full, filesystem or
storage-controller durability qualification. Read-only SQLite may interact with
existing WAL/SHM according to SQLite's own rules; this slice does not delete or
repair sidecars or claim zero filesystem metadata effects for every reader.

The connection/settings, local snapshot checks and writer transaction do not make
external consent updates, the later model sink, or disclosure delivery one atomic
transaction. No durable model-delivery or execution replay ledger is added.
No full repository CI, installed-wheel test of this new slice, Linux test, live
model comparison, external independent source review, personal pilot or production
qualification is claimed.

C0 remains **UNVERIFIED/HOLD**; native T11/T12 remain **UNEXECUTED**. The next
product wiring can replace the old demo's receipt sidecar with this store under a
separate reviewed change. This local commit does not perform that switch.

Evidence, generated manifests, patches and Git bundles are stored outside the
repository source tree. A Git bundle with the verified public parent prerequisite
preserves both recovery and this implementation without requiring a push. The
final candidate manifest binds the commit/tree, all three payload files and actual
receipts. It is an unsigned integrity record, not an owner authority grant.
