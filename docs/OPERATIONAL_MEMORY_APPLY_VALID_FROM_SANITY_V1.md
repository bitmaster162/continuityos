# Operational Memory Apply valid_from Sanity v1 (R50)

R50 closes the existing-memory counterpart of the R49 fresh-bootstrap temporal-poisoning defect.

On the R49 CI-built wheel, an R36 delta containing a claim with `valid_from=9999-12-31` and an otherwise current valid R37 authorization produced R44 READY and R37 PASS. R37 writes claim events with `occurred_at=valid_from`, so the OperationalMemory projection advanced to year 9999 even though `apply_recorded_at` was current.

R50 extends the already-shared R37/R44 temporal authorization boundary. For every `RECORD_CLAIM` or `SUPERSEDE_CLAIM` operation with an explicit `valid_from`, the operation must satisfy:

`claim.valid_from <= apply_recorded_at`

If `valid_from` is omitted, R37 already defaults it to `apply_recorded_at`; that behavior remains valid. Historical `valid_from` values remain valid. `valid_to` is intentionally not upper-bounded, so a current claim may still carry a future expiry.

R44 and R37 reuse the same authorization validator, so the invalid proposal is rejected during read-only preflight and again by the effectful gate before a write transaction. The R46 authority wall-clock guard and R48 exact replay-authorization guard remain composed on the same R37 import path.

No new authority, identity-authentication claim, memory permission, accepted truth, canonical-state mutation, deployment, dispatch, trading, wallet access, or capital permission is introduced.
