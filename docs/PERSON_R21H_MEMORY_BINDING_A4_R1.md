# Person R21H — exact saved Memory binding (A4 R1)

Base: `b11af1a69957e77accc0a6d74dedb7c4dab8ee28`, tree
`69893ca2d8417c5b1904863b97e506f536168134` (Draft PR #213).
Scope: local A4 repair, not A3, a new runtime, an authority issuer, or a schema migration.

## Reproduced defect

An existing durable admission bound `memory_id=3`. A trusted-host read intent
selected another row `memory_id=4` with identical text and namespace. R2/R4
validated the Person/source candidate, while R21H checked the selected row
against the intent and content only. The recording model received `mem:4`.
Different text, namespace, superseded metadata and absent rows were already
rejected. This was a P2 exact-source-reference defect, not a reproduced
cross-tenant disclosure or arbitrary-content read.

## Correction and compatibility boundary

R21H admission stores must now implement:

```python
read_current_memory_binding_bytes() -> bytes | None
```

The unchanged R4 protocol and evaluator do not acquire this requirement. It is
required only when a host configures `PersonTwinR21HEvidenceAdapter`. The durable
`PersonTwinAdmissionStore` implements the method by calling the existing
`load_current()` and projecting the saved binding plus CURRENT commitments from
that single verified snapshot. No intent, requested id or namespace is passed
to this read method. It does not read from a second database, create a schema,
write an admission, cache ALLOW, or issue fresh consent/authority.

The canonical UTF-8 JSON readback contains exactly:

- `schema = continuityos.person-twin.r21h-memory-binding/v1`;
- `pointer_sha256`, `candidate_sha256`;
- `memory_id`, `namespace`, `person_record_id`, `source_record_id`.

The adapter compares exact canonical bytes to its independently pinned intent
and R4 context **before** selecting the Memory row. Missing method, non-callable
method, read exception, no CURRENT, malformed/noncanonical bytes, extra fields,
duplicate keys and any binding mismatch deny the request. There is no fallback
to content-only matching. Existing integrations supplying only the minimal R4
read-store interface now deliberately fail closed at R21H until they implement
this saved-binding read contract; do not synthesize the value from request pins.

The repository's earlier in-memory R21H test store was extended only in its test
fixture: it saves the binding once after actual fixture admission/Memory seeding,
before a read intent or provider is constructed. The existing demo uses the
durable store and needs no change. Non-Person runtime paths are untouched.

The saved-binding read runs independently in both prepare and final prompt
validation. Public receipt keys and schema are preserved exactly; no new public
commitment field is added. A changed binding after prepare denies before model
generation. The existing demo keeps its exact-key receipt validator unchanged.

## Validation and limits

Acceptance bodies from the prior A3/A4/N4 reproduction are preserved unchanged;
only their test import origin is redirected to this local checkout. The baseline
must reproduce A4. After correction A4 must become green while A3's documented
publication-result ambiguity remains red. A3 is not silently reclassified or fixed.

New tests exercise warm chat and cold streaming, exact/identical-other/mismatched
rows, unavailable and corrupted readback, prompt-boundary drift, query-only reads,
no-CURRENT and suspended-store rejection. Existing R1-R4, R21H, demo, export,
backup and restore tests are included in local qualification. Run counts and
source hashes belong to the external immutable execution manifest, not a claim
that all repository tests or official wheel CI ran.

The read port remains a trusted-host integration boundary, not a cryptographic
attestation or authentication of arbitrary Python objects. A malicious host that
supplies fabricated stores/identities is not solved here. Database identity across
distinct read stores, generation/ABA handling (A6), receipt provenance (A5), H3/C0
native identity, independent revocation-witness freshness and real model egress
remain separate requirements. Restore continues to require a fresh external
revocation ledger. No production or live-data qualification is asserted.

`NOT_PRODUCTION_ADMITTED`; `C0 HOLD`; `T11/T12 UNEXECUTED`;
`execution_authority=NONE`; `can_execute=false`; `can_trade=false`;
`capital_permission=DENY`. No push, PR mutation, merge, deploy, Scheduler, TPM,
installed-runtime change or real Memory access is part of this local stage.
