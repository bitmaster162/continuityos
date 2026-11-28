# Person Twin acceptance matrix — 2026-11-28 R1

**Decision: HOLD for Person Twin production admission. Substantial bounded implementation is present.**

This is a factual map of the twelve acceptance families in [issue #144](https://github.com/bitmaster162/continuityos/issues/144), not a new approval, executable gate, runtime generation or claim of production readiness. It accompanies [the machine-readable matrix](person_twin_acceptance_matrix_20261128.json).

The source baseline is **`cc889675df6e54cf7caa759e9aca6b032c217429`**, tree **`36fdb7de3a08c457056ccdbb1830c7fba8af2232`**, in `bitmaster162/continuityos`. Source hashes and exact test-function references in the JSON are derived from those Git objects, not from later worktree edits. A candidate built after that baseline needs its own validation; this document must not silently acquire a new baseline.

## What the evidence supports

Identity, consent, privacy/provenance, staged admission, durable SQLite admission, read authorization/replay checks and the protected R21H evidence path have code and synthetic tests. The current Person continuity demo is wired to the durable store and recovers the actual admission receipt in new processes. It is incorrect to describe these components as merely plans.

It is also incorrect to infer production admission from this implementation. All reviewed Person outputs retain `NOT_PRODUCTION_ADMITTED`, `execution_authority=NONE`, `can_execute=false`, `can_trade=false` and `capital_permission=DENY`. H3 C0 remains `UNVERIFIED/HOLD`; native T11/T12 are `UNEXECUTED` in the reviewed evidence. The matrix does not inspect an installed runtime, the owner's database, live models, vault bytes or an external human signoff receipt.

The audit read code, test definitions, documentation and GitHub status metadata. It did **not** execute the Person runtime/tests. Existing historical execution narratives are labelled as source-backed and unreproduced by this audit. Multiple documents or reviewers using the same repository/fixtures do not create independent source authenticity or owner authority.

Subsequent implementation validation is recorded separately in [the continuity trust repair](CONTINUITY_TRUST_REPAIR_20261128.md). Its candidate test results do not change this source matrix's baseline or supply production admission evidence.

## Twelve-family map

“Implemented” below refers to the stated bounded code scope. “Remaining” describes evidence needed to close the broader family; it does not assert that an uninspected external artifact is absent everywhere. No family is marked production accepted by this map.

| Family | Code and wiring at this baseline | Remaining acceptance evidence |
|---|---|---|
| **Identity** | R1 constructs deterministic tenant/subject `twin_id`, owner/controller/epoch bindings and a fingerprint. R2/R3/R4 and the durable store consume them. Demo identity is selected before reading its synthetic database. | Authenticated real subject/controller and trusted installation/root binding; C0/H3 identity evidence; exact production signoff. |
| **Consent** | Immutable source-consent receipts, distinct read/admission authorities and a separate revocation ledger. Consent is rechecked through R2, admission, R4 and final prompt validation. | Authenticated consent issuer, trusted current time and independently fresh revocation; exact model-egress authority and the remaining check-to-disclosure interval. |
| **Admission** | R3 stages `COMMITTED_NOT_CURRENT` before postverify and promotion. Durable storage commits CURRENT, publication and the actual receipt together; a fresh connection verifies the result. Demo R2 reuses these saved bytes. | Hostile rollback/rewrites, generation/ABA and production storage-failure evidence; no atomicity is claimed across admission, external consent and model delivery. |
| **Privacy** | Exact Person private/shared scopes, no implicit widening, current-consent filtering and cross-scope lineage hiding. Protected R21H composes R2/R4. | Qualification of every actually enabled pilot route, including direct database/filesystem access, backup/export and egress. Generic runtime does not inherit protected Person qualification. |
| **Provenance** | Source object/revision, observed/effective time, content, actor/authority, consent and admission identity are bound. A4 verifies the exact saved Memory ID/namespace before selection and again at prompt construction. | Source/issuer/time authentication, exact database identity across separately supplied stores, A5 receipt provenance and A6 generation/ABA obligations. |
| **Backup / Portable Twin Vault** | Generic Memory has quiescent byte-exact SQLite backup, manifest and readback primitives. These are existing reusable assets. | A Person-specific portable vault contract and composed implementation, including inclusion/exclusion, consent/privacy, encryption/key custody, schema compatibility and complete package verification. The demo is explicitly not a vault proof. |
| **Restore** | Generic Memory restore pins target hash, requires explicit compatibility/replace confirmation, retains a preimage and verifies atomic replacement/rollback on synthetic databases. | Person vault-to-restore composition, authorized state/replay equivalence, fresh revocation after restore and admission/promotion rules. The external N4 body mentioned in A3 documentation was not available in this reviewed set. |
| **Export** | R2 builds a Person-filtered, deterministic P2 export bundle with provenance and current-ledger binding. It remains read-only and non-admitted. | Exact requester/destination/recipient authority, delivery/readback and portable restore compatibility. R4's READ/PROPOSE/APPROVE support does not constitute a complete export service. |
| **Lifecycle** | R2 provides an exact twin/record/scope target binding with `physical_delete=false`. Shared P2 code has retention, hold, tombstone and advisory purge-eligibility primitives. | Demonstrated reuse in the exact persistent Person lifecycle path, owner authority and reconciliation. A read-only target binding is not a completed lifecycle transaction. |
| **Replay** | R4 derives and checks exact admission/source/consent/policy/session/authorization replay identity through an external read interface. R21H has one-use request-phase checks. | Durable atomic disclosure/replay custody across restart, concurrency, ambiguous delivery and generation changes. Demo `_EmptyReplayFixture` is not a durable delivery ledger. |
| **Authority** | R4 composes stored-current readback, exact session/authorization and policy. Agent READ/PROPOSE are non-effectful; APPROVE requires human identity; EXECUTE and outside-R4 actions are denied. | Independently authenticated host/context/intent and C0 same-binding native identity; evidence for all enabled routes and revocation/kill behavior. |
| **Operator signoff** | Code rejects admission escalation and continues to emit the non-admitted ceiling. | A separate human signoff bound to the exact accepted commit/tree/evidence set after the required family evidence. A named acceptance owner for that exact gate is not inferred here. |

For every row, the JSON lists code symbols, existing test functions, file SHA-256/Git blob identities, prior-run limitations and the remaining evidence. This allows a subsequent reviewer to verify the concrete scope without treating the table as a new authority source.

## Corrected historical readings

### A3 is present in current code

The older [A4 document](PERSON_R21H_MEMORY_BINDING_A4_R1.md) says A3 publication-result ambiguity remained outside A4's scope. That is a historical statement about the A4 stage. The later [A3 document](PERSON_ADMISSION_PUBLICATION_RESULT_A3_R1.md), current `PersonTwinAdmissionStore._result` and `test_a3_*` cases show that the baseline now distinguishes `attempt_publication_id` from `publication_id`, which is populated only after a confirmed promotion COMMIT.

Therefore the **result-field A3 defect must not be repeated as currently unfixed**. Confirmed COMMIT still does not mean successful postcommit readback, fresh authority or confirmed delivery. A5/A6 and other independently scoped obligations remain separate.

### The demo already uses durable admission

The original [durable-admission R1 document](PERSON_TWIN_DURABLE_ADMISSION_R1.md) describes an earlier stage where the public Person demo still used a sidecar fixture. [Demo R2](DEMO_PERSON_CONTINUITY_R2.md), `person_twin_demo.py` and its product tests supersede that wiring statement: PREPARE writes the real admission bundle into its temporary SQLite database; A/B reopen it read-only; reader admission writes and the old sidecar path are rejected.

This is a bounded process-continuity composition with recording model clients. It does not establish live model quality, native identity or Portable Twin Vault restoration.

### Closing #144 did not supply the missing signoff

GitHub reports [#211](https://github.com/bitmaster162/continuityos/pull/211) merged at **2026-10-15 15:37:55 UTC**, and [#144](https://github.com/bitmaster162/continuityos/issues/144) closed as completed at **15:37:58 UTC**. The PR body explicitly states that it does not close #144, limits evidence to synthetic data/recording clients and retains `C0 HOLD`, `T11/T12 UNEXECUTED` and `NOT_PRODUCTION_ADMITTED`.

Both observations are preserved. The issue's closed metadata is not a twelve-family acceptance receipt. This audit does not mutate the issue or rewrite earlier evidence.

## Validation and freshness

[Review-gates run 43390212172](https://github.com/bitmaster162/continuityos/actions/runs/43390212172) reports success for both Ubuntu and Windows Python 3.11 on the exact baseline. The job IDs are **131768040828** and **131768040401** respectively. On 2026-11-28 the artifacts endpoint returned an empty artifact list, so this audit did not reread per-test or benchmark receipts. The workflow's receipt retention is 14 days; repository status is confirmed, detailed expired execution evidence is not reconstructed.

Historical documents report:

- Durable admission R1: **294 passed / 1 skipped**, with the then-new 52 durable cases passing in the stated Windows environment.
- Durable demo R2: **320 passed / 1 skipped**, with 52 runnable product cases passing and a separate command-entrypoint observation. Its earlier incompletely diagnosed setup failure remains a reproducibility caveat.

These are source-backed historical reports, not new counts for this baseline or the later improvement branch. A skipped native/platform path is not a passed path.

### Smallest relevant compatibility selection

The following selection exercises the Person composition using temporary synthetic SQLite, recording model clients and bounded child Python processes. It is a validation plan here, not an execution receipt:

```text
python -m pytest -q
  tests/test_person_twin_admission_contracts.py
  tests/test_person_twin_privacy_provenance.py
  tests/test_person_twin_admission_coordinator.py
  tests/test_person_twin_authority_replay.py
  tests/test_person_twin_admission_store.py
  tests/test_person_twin_r21h_evidence.py
  tests/test_product_person_continuity.py
```

Pass those paths to one pytest invocation. This selection requires no live LM Studio, owner database, TPM or PostgreSQL service. The two Windows-venv cases skip elsewhere; the real symlink case may skip if the host disallows symlink creation. Separately, crypto-backed fixtures require the optional `cryptography` package. The wider test suite also contains legitimate loopback HTTP tests, so a blanket socket-deny wrapper must not be represented as compatible with every repository test.

Hardware/provider names in unit tests do not establish real environments: the inspected TPM/H3/PostgreSQL-oriented unit fixtures include fake providers. Native T11/T12 and separately approved provider qualification remain distinct from their unit results.

## Next acceptance boundary

Use this map to resolve the exact evidence requirements of the chosen integration work order. Keep repository corrections and synthetic tests separate from global queue status, installed runtime changes and production admission. Reuse the implemented contracts; do not replace R21H or create a second memory system merely to rename unresolved work.

Before claiming production admission, bind all required family evidence, negative/bypass cases, exact code identity, independent acceptance review and the separate human signoff to one candidate. Any previously uninspected receipt can improve this map only after its identity, scope, provenance and applicability are verified. This document creates neither that receipt nor permission for live data, deployment or client connection.
