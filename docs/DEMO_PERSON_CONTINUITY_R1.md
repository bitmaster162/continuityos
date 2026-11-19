# Person continuity demo — R1

Status: local candidate; scoped tests and installed-wheel demo PASS.
Work order: `COS_DEMO_PERSON_CONTINUITY_R1`.
Base commit: `28bfce3c1900d11bcc90fdd9428295ce18c68b14`.
Base tree: `fcb37ef8d9af2c349a62c576b5634798881a7fbe`.

## User outcome

`cos demo person-continuity` demonstrates a bounded Person/R21H read across a
real process boundary. A later process recovers the admitted synthetic goal,
current decision, constraint and next step from persisted inputs, and the demo
checks the exact evidence delivered to the recording model client.

The existing Memory SQLite and R21H FAST runtime are reused. The demo composes
real R1 identity/consent, R2 privacy/provenance, R3 admission transitions and R4
READ evaluation. Its model client records arguments; it performs no inference
and supplies no model-quality or model-latency evidence.

## Entrypoint

```bash
cos demo person-continuity
cos demo person-continuity --json
```

This command is a synthetic local product proof. The ordinary user's database,
external AI providers and native H3 are outside its input surface.

The existing current-session containment continues to apply. A bound read-only
session must HOLD before demo filesystem or subprocess effects. Supplying a
user database through the public `--db` argument is rejected.

## Process and data boundary

The public orchestrator directly owns three sequential child processes:
PREPARE, A and B. Socket-denial instrumentation is installed inside each child;
the calling application's audit hooks are not changed. The parent owns each
process handle and its timeout/reap boundary, with no worker grandchildren.
Each read worker creates its own runtime, synthetic model profile, session,
request and intent. Worker A exercises warm FAST chat and worker B exercises
cold FAST acquisition.

Child imports are pinned to the parent's actual package root and demo source
SHA-256, using isolated Python startup. A different working directory or
`PYTHONPATH` cannot silently select a different demo module. This is an import
consistency check over the trusted local package, not source-origin attestation.

One owned temporary directory contains one Memory SQLite database and bounded
canonical fixture bytes. The PREPARE process uses the existing R3 transition
API before the workers run. It persists the candidate, CURRENT pointer and
admission receipt bytes required for subsequent R4 readback.

PREPARE seeds the synthetic scenario. A and B independently recover that saved
scenario; neither reader is claimed to have originated a real owner's decision.

The declared fixture clock is `2026-08-25T12:50:00Z`. Consent, delegation and
currentness checks use that synthetic clock. Real execution timestamps are
reported separately; the demo does not authenticate the current time or a live
owner's authorization.

Worker B receives persisted input paths and commitments. It does not inherit
the earlier runtime, a ready prompt or an answer. Memory rows are not recreated
during B's read. The recording model's actual prompt is the proof surface.

Three kinds of evidence must remain explicit in the result:

| Input | What the demo can establish |
|---|---|
| Memory SQLite bytes | The synthetic memory survived closing and reopening in another process. |
| Persisted admission fixture bytes | The bounded R3 candidate, pointer and receipt were read back and checked. |
| Fresh synthetic host/session inputs | Each worker constructed different test session and request bindings. |

The admission fixture is test input. It is not a production persistent
AdmissionStore, a second canonical database, an export, a Portable Twin Vault
or independently authenticated owner authority. A saved approval never becomes
a fresh authorization merely because it was persisted.

## Acceptance requirements

The implementation must establish all of the following before a PASS is recorded:

- Successful, separately observed PREPARE, A and B process outcomes.
- A and B use distinct process/session/request identities and model profiles.
- Both protected READ paths bind the same exact current memory reference and
  evidence content; old and foreign sentinels are excluded.
- The recovered goal, decision, constraint and next step come from the model
  prompt's actual evidence projection.
- The SQLite and fixture bytes are unchanged by the worker reads.
- Tampered persisted evidence, revoked consent or stale currentness fails closed
  before model generation. Existing R4 action semantics remain unchanged.
- Public database overrides, malformed worker inputs, invalid receipts and
  containment failures do not become success.
- Socket operations are denied in the isolated PREPARE, A and B children; no live
  model, connector, credential or external-network operation is part of the demo.
- Each child has a finite timeout of at most 20 seconds, plus bounded termination
  and pipe-reader join grace periods; the argument is a per-child deadline.
  Fixed fixture members are checked within the owned temporary directory without
  following symlinks; parent traversal components and unexpected members fail closed.
- Timeout, worker failure or cleanup failure excludes PASS. Reported effects and
  cleanup outcomes describe observations, not unconditional defaults.

The tests target the new composition and process boundaries. Existing generic
demo, current-entrypoint containment and Person/R21H suites remain compatibility
evidence.

## Scope of this result

This is a synthetic fresh-process Person continuity proof. It does not establish
cross-model reasoning quality, complete authorized-state restore equivalence,
R5 lifecycle/export completion, Portable Twin Vault readiness, the full P3
cross-gate acceptance family, native broker authentication or a real-data pilot.

Project admission remains `NOT_PRODUCTION_ADMITTED`.
H3 C0 remains `UNVERIFIED/HOLD`; T11/T12 remain `UNEXECUTED`.
Execution, deployment and trading authority are not granted by a demo PASS.

## Validation record

The final scoped run on 2026-10-12 UTC used Python 3.12.14 and pytest 9.1.1:
**169 passed, 0 failed, 0 skipped**. The selected source/test hashes were identical
before and after execution. A separate parent audit hook denied socket events;
zero parent socket events were observed. Child audit scope is reported separately
by each real PREPARE/A/B receipt.

| Suite | Passed |
|---|---:|
| `tests/test_product_person_continuity.py` | 27 |
| `tests/test_product_demo.py` | 8 |
| `tests/test_current_entrypoint_containment_v1.py` | 11 |
| `tests/test_person_twin_r21h_evidence.py` | 73 |
| `tests/test_person_twin_authority_replay.py` | 50 |
| Total | 169 |

Reproduce the selected test set from the checkout with the existing test tooling:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
python -m pytest -q -p no:cacheprovider \
  tests/test_product_person_continuity.py \
  tests/test_product_demo.py \
  tests/test_current_entrypoint_containment_v1.py \
  tests/test_person_twin_r21h_evidence.py \
  tests/test_person_twin_authority_replay.py
```

The recorded run used those pytest arguments inside the separate offline audit
recorder. The shell command above alone does not install that parent audit hook.
The developer's earlier 27-case run repeats the new cases and is not added to
the 169-case total.

The new tests independently inspect SQLite through a read-only immutable
connection and compare its rows and bytes with both real workers' results.
The same positive run puts a failing shadow package in CWD and `PYTHONPATH`;
all children still use the expected parent package. Negative tests exercise
revoked consent, stale session bindings, changed or missing persisted bytes,
database override rejection, direct current-session containment, symlinks,
parent traversal and malformed or contradictory receipts. Real child processes
exercise timeout and output limits, with termination checked through their
actual `Popen` handles. A forced cleanup failure changes an otherwise successful
three-child run to HOLD.

### Installed-package observation

The wheel was built locally with the available setuptools backend, without
fetching dependencies, and installed into a new isolated Python environment.
The installed `cos` script was executed through `runpy.run_path` with arguments
`demo person-continuity --json`, under Python `-I -B` and a parent socket-denial
audit hook. The package imported from that environment's `site-packages`, with
the source checkout absent from `sys.path`; no tests are packaged in the wheel.

The installed demo returned `COS_DEMO_PERSON_CONTINUITY_PASS` with three observed
direct children, each exited zero and reaped. PREPARE, A and B reported the same
frozen demo source SHA-256. A used one warm chat call and B one cold streaming
call. The exact current evidence and persisted SQLite/fixture hashes agreed;
session, request, packet, intent and R4 commitments differed. Parent and child
socket event counts were zero, and temporary cleanup was observed successful.

The recovered synthetic context was:

- Goal: continue the approved synthetic project.
- Decision: keep the read-only Person/R21H evidence path.
- Constraint: synthetic data only; no external effects.
- Next step: inspect the recovered current context in session B.

These fields were extracted from the actual evidence delivered to the recording
client. They are not a generated model answer or real owner's remembered state.

### Tested source identities

| File | SHA-256 |
|---|---|
| `continuityos/person_twin_demo.py` | `2c1f95648f5c321555bc0ae7bf23e42195de6cd84bf4bbcf0ae4a7747556f417` |
| `continuityos/demo.py` | `e13dcc28ae1ee46e95b809ba3170808e6e3c3faf132b0b736d8074440cc62a49` |
| `tests/test_product_person_continuity.py` | `5098be2d8a60c6216e30f1113a7ca4a1a07c8241267df5be121f8706052762b7` |

The local candidate manifest binds the final four-file payload and external
validation receipts. The observations establish this local synthetic composition;
they do not authenticate a hostile same-user filesystem, an independently
authenticated host or an atomic admission/SQLite/model-delivery transaction.
New GitHub CI and Windows execution were not performed for this local candidate.

Independent source/test review passed on the exact hashes above. Review findings
about path traversal, child import consistency, receipt validation, process
identity and observed effects were resolved before the final scoped run. The
implementer, test author and reviewer were separate agent roles sharing the same
repository and fixture lineage; this is not independent owner attestation.
