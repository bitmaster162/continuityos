# A3 R1: distinguish an attempted publication from a confirmed COMMIT

Scope: the outer result of `PersonTwinAdmissionStore.admit()` only. Parent:
`fe04df409f86bc773d7210dbfaefa620afc3a231`, tree
`8b52fb2e3986e2c159cbcf38e0e56497e0369b4a` (local A4 candidate).
This correction is not a new admission issuer, SQL schema, R3/R4 algorithm,
backup/restore implementation, runtime generation or production admission.

## Reproduced defect

On the parent revision, denial immediately before the promotion COMMIT returns
HOLD / `commit_state=NOT_ATTEMPTED`, yet `publication_id` contains a generated
identifier absent from `person_admission_publications`. The staged candidate may
already be committed separately. A failed re-publication preserves the previous
CURRENT but similarly returns an identifier for the failed attempt.

No successful authorization was observed on these HOLD paths. The defect is an
ambiguous result contract, not a demonstrated bypass of HOLD or a data breach.

## Result contract

The existing outer result schema name remains
`continuityos.person-twin.durable-admission/v1`. This is an additive field plus a
narrowing of the meaning of its existing `publication_id` field:

- `attempt_publication_id`: the identifier allocated to this invocation's
  prospective publication; null if no identifier was allocated. It can be used
  for later explicit reconciliation. It is not proof of persistence, freshness,
  authorization or successful rollback.
- `publication_id`: populated only when this invocation's promotion
  `commit_state` is `CONFIRMED`. It equals `attempt_publication_id`. Otherwise
  it is null. It never substitutes the pre-existing CURRENT identifier.
- `commit_state`: unchanged: `NOT_ATTEMPTED`, `UNKNOWN`, `CONFIRMED` describe
  the promotion COMMIT observation. Candidate COMMIT state remains separate.
- `status`: unchanged. PASS still requires confirmed promotion and successful
  fresh readback. A confirmed COMMIT can still be reported as HOLD when fresh
  readback fails. Such a HOLD retains its confirmed `publication_id` but returns
  no `admission_receipt` and grants no permission.

| Observed case | attempt_publication_id | publication_id | Status / commit_state |
| --- | --- | --- | --- |
| Rejected before allocation | null | null | HOLD / NOT_ATTEMPTED |
| Rejected after allocation, before COMMIT | attempt ID | null | HOLD / NOT_ATTEMPTED |
| Promotion COMMIT response uncertain | attempt ID | null | HOLD / UNKNOWN |
| COMMIT confirmed, fresh readback failed | attempt ID | same ID | HOLD / CONFIRMED |
| COMMIT confirmed, fresh readback verified | attempt ID | same ID | PASS / CONFIRMED |

If the COMMIT response is lost after SQLite actually commits, `publication_id`
still remains null: the operation could not confirm success. The attempt ID is
retained for investigation. If COMMIT fails before persistence, the same public
UNKNOWN result is conservative even when a later read proves there is no row.
The implementation does not automatically retry, reclassify UNKNOWN, or erase
possible effects. `ROLLBACK_UNVERIFIED` still suspends the store and retains
`possible_persisted_effect=true`.

A non-null `publication_id` confirms the observed COMMIT on that connection; it
does NOT by itself attest current database-path identity, continued CURRENT
status, fresh consent, or successful post-COMMIT verification. Consumers must
continue checking the complete result and obtaining fresh authorization.

## Compatibility boundaries

The change affects only the outer Python outcome dictionary. Existing SQL DDL,
stored candidate/pointer/binding/R3 receipt bytes, `AdmissionSnapshot`, CURRENT
semantics, transaction ordering, public R21H evidence receipt and the product
demo's strict receipt validators are unchanged. There is no data migration.
Strict consumers of the outer dictionary must accept the newly documented
`attempt_publication_id`. Consumers previously treating every `publication_id`
as an attempt identifier must use the new field instead.

## Tests and acceptance evidence

The existing independent A3/A4/N4 acceptance bodies are rerun without changes.
A3 must change from red on the parent to green; A4 exact row binding and the
backup -> revoke -> restore test with a fresh external ledger must stay green.

Nineteen new synthetic cases cover early and late denials, confirmed success,
COMMIT response loss before/after actual SQLite COMMIT for both phases, failed
or mismatched post-COMMIT readback, failed re-publication, identifier reset and
unverified rollback. Existing test bodies are preserved. All DBs are temporary.
A separate deterministic review compares old/new result functions across state
combinations and verifies that transaction methods and guards are unchanged.
Actual test receipts and the candidate manifest are external build artifacts.

## Remaining limits

Local synthetic tests do not replace fresh official wheel/CI, independent review
of this specific change, or owner signoff. A4 still has its own local candidate
and publication status. A3 does not address trust-origin, stale external ledger,
legacy effect-path bypass, OS isolation or cross-machine restoration questions.

`NO_PUSH`, `NO_PR_MUTATION`, `NO_MERGE`, `NO_DEPLOY`, `C0 HOLD`,
`T11/T12 UNEXECUTED`, `NOT_PRODUCTION_ADMITTED`, `can_trade=false`,
`capital_permission=DENY` remain in force for this local stage.
