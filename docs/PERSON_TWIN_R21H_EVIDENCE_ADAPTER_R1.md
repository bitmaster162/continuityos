# Person evidence in R21H — R1 integration candidate

Status: local synthetic integration candidate; `NOT_PRODUCTION_ADMITTED`.

## Why this change exists

R21H already answers from ContinuityOS memory. Its generic evidence path converts
ranked memory rows into `TwinEvidence`, without composing the Person admission,
privacy/provenance and authority/replay contracts. This candidate adds an explicit
controller-configured path for one admitted CURRENT context snapshot.

The snapshot can contain a goal, current decision, constraint and next step.
It keeps a real SQLite `mem:<id>` reference. The existing Memory store and R21H
model transport are reused; no second canonical store or new retrieval engine
is introduced.

## Source composition

- Protected master baseline: `719ed32a64301fc8083a5aad0c4ed7bed316040e`.
- Baseline tree: `0406a3020f86e405b7934ea50764d0f7e64ee63d`.
- The R4 module and its original tests are imported byte-for-byte from
  PR #150 head `4515bea19978b522328607deb493a55234ef7d4c`.
- R1, R2 and R3 remain the existing master implementations.
- Historical R21B–R21G overlays remain unchanged.

Importing R4 into this candidate does not merge PR #150 or grant pilot admission.

## Request boundary

An explicit `PersonReadIntent` pins the question hash, current-session hash,
authorization request and packet, memory ID and namespace, Person and source
record IDs, principal, scope, privacy class and purpose. A separate host-supplied
provider supplies the current R4 context. Neither the question nor memory metadata
is used to construct authority.

The adapter composes R2 privacy/provenance filtering and the R4 READ decision
before fetching the exact SQLite row. It binds that row to the validated source
payload text and namespace. Metadata can veto a retired or malformed row; it
cannot grant access. Only the verified projection is converted to model evidence.

Immediately before prompt construction, the protected runtime repeats the context
and row checks and compares the new projection with the pending evidence. A
missing binding, changed session, revoked consent, stale admission, mismatched
source text or changed evidence stops the request. Adapter validation errors use
fixed codes; raw R4 failure details and authority inputs are not copied into
model prompts. Existing model-transport error behavior is retained.

Each successful answer carries a bounded decision receipt in
`answer.stats['person_evidence']`. This is an unsigned integration observation,
not a signed owner grant or an external trust attestation.

## Deliberately limited runtime surface

Protected mode covers R21H FAST with the streaming transport contract, including
warm chat and cold streaming acquisition. It rejects DEEP, legacy fallback,
startup prewarm and direct protected helper use outside the active request.
The request frame is scoped to the runtime lock and is cleared after completion
or failure.

The generic runtime remains available when no adapter is configured. Its
compatibility behavior does not become Person-qualified by this change.
The class-level prompt formatter used by generic DeepLite is retained.
No CLI, HTTP, MCP or DeepLite option enables the new protected mode.

## What the synthetic proof can establish

The new tests use temporary synthetic SQLite records, the real R2/R3/R4 contracts
and recording fake model clients. Two fresh runtime instances receive the same
admitted snapshot through separate fixture sessions and authorization chains.
The test inspects the actual prompts and memory IDs delivered to those clients.
Old and unrelated records are excluded from that projection.

Negative cases exercise identity, consent, scope, session, query, row-currentness
and final-check failures, plus attempts to enter an unsupported runtime path.
Existing FAST and generic runtime tests cover compatibility.

This is a two-session transport/composition proof. It is not a comparison of two
live models, a scientific Person Twin benchmark, an end-user retention metric,
or a completed backup/restore or coding-tool interception demonstration.

## Trust and release limits

The host, intent issuer and context provider remain trusted integration inputs.
The adapter checks consistency and readback; it does not authenticate those
inputs independently. It does not establish trusted time, owner key custody,
model-sink egress consent or native same-binding broker identity.

Repeated checks reduce the specific stale-evidence window exercised by the tests;
they are not an atomic transaction across admission, SQLite and the model sink.
R4 READ decisions do not reserve durable disclosure intent or prove delivery.
R4 still authorizes no execution, deployment or trading.

H3 C0 remains `UNVERIFIED/HOLD`; native T11/T12 remain `UNEXECUTED`.
The successful G3 object-compilation workflow is separate evidence.
The twelve P3-P1 gate families and owner signoff remain separate acceptance work.

Before a real personal pilot, a separately reviewed integration must supply
authenticated authority and currentness inputs, approved database custody and
egress, and coverage for every enabled route. This candidate does not enable
that pilot.

## Validation record

Observed 2026-10-12 19:03:36–19:03:38 UTC (2026-10-13 Asia/Bangkok):

| Test group | Result |
|---|---:|
| New Person/R21H composition and negative cases | 61 passed |
| Unchanged R4 authority/replay tests | 50 passed |
| Existing R21G/R21H, generic runtime and DeepLite compatibility | 43 passed |
| Total | 154 passed; 0 failed; 0 skipped |

Python 3.12.14; pytest 9.1.1; plugin autoload/cache/bytecode disabled.
All `socket.*` audit events were denied; zero were observed. Tested source hashes
were identical before and after the run. This was a scoped local run, not the
entire repository suite or Windows qualification.

The independent source review found and the regression tests reproduced direct
and nested DEEP dispatcher entry before rejection, and nested FAST dispatch.
The revised runtime rejects these before the affected client operations and
preserves the outer request. The final reviewed source has no remaining blockers
within the trusted-host integration scope described above.

| Tested file | SHA-256 |
|---|---|
| New adapter | `a918dde064962e78aaa60b9e5b8dd28d93034afd7a5e6a1a2be3a3984ddf89ec` |
| R21H runtime | `ca94b260b256125121e416d992504bf71bd0e8af8f2706084c5e3752c224cfa4` |
| New adapter tests | `fe7220f15bb5e58cd57cf40ec730465b03af50d3de970e8b9a968a3bd5b8e817` |

The unsigned local run receipt has SHA-256
`6a1f75c3c6bf18fac2745f479cda599ac0e9d22d9f628f6945744775277b3b85`.
It records the 154 test outcomes and exact inputs; it is not an authority grant.

Reproduce the scoped run from the repository in an environment with pytest:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python - <<'PY'
import sys

def deny_socket(event, args):
    if event.startswith('socket.'):
        raise RuntimeError('PERSON_R21H_VALIDATION_NETWORK_DENIED:' + event)

sys.addaudithook(deny_socket)
import pytest
raise SystemExit(pytest.main([
    '-q', '-p', 'no:cacheprovider',
    'tests/test_person_twin_authority_replay.py',
    'tests/test_person_twin_r21h_evidence.py',
    'tests/test_sovereign_twin_runtime.py',
    'tests/test_sovereign_twin_r21g_fast_chat_coupled_streaming_jit.py',
    'tests/test_sovereign_twin_r21h_fast_startup_streaming_jit_prewarm.py',
    'tests/test_sovereign_twin_r21h_legacy_client_compatibility.py',
    'tests/test_sovereign_twin_r21h_cached_success_revalidation.py',
    'tests/test_sovereign_twin_deep_lite.py',
]))
PY
```
