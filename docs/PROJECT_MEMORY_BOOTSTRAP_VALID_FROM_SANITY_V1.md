# Project Memory Bootstrap valid_from Sanity v1 (R49)

R49 closes a third fresh-bootstrap temporal-poisoning path found after R46/R47.

On the R48 CI-built wheel, a manifest with current `bootstrap_recorded_at` and claim `recorded_at`, but `claims[0].valid_from=9999-12-31`, produced R41 READY and R38 PASS. R38 records claim events with `occurred_at=valid_from`, so the fresh OperationalMemory projection advanced to year 9999.

R49 extends the existing composed bootstrap temporal boundary. After the exact R38 authorization validates, every bootstrap claim must satisfy:

`claim.valid_from <= bootstrap_recorded_at`

The rule is intentionally limited to `valid_from`. `valid_to` may remain in the future, so a currently valid claim can still carry a future expiry. Historical `valid_from` values and equality with bootstrap authority time remain valid.

R41 and R38 reuse the same authorization boundary, so the invalid manifest is rejected in read-only preflight and effectful bootstrap before target/temp creation. R40 target-path canonicalization, R46 authority wall-clock sanity, R47 manifest record-time sanity, and R49 valid-from sanity remain composed on the same R38 import path.

No new authority, identity-authentication claim, memory permission, accepted truth, canonical-state mutation, deployment, dispatch, trading, wallet access, or capital permission is introduced.
