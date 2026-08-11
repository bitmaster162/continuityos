# Project Memory Bootstrap Record-Time Sanity v1 (R47)

R47 closes a second bootstrap temporal-poisoning path discovered after R46.

R46 bounds the R38/R41 authorization timestamp itself, but the R38 manifest also carries `claims[].recorded_at` and `proposed_decisions[].recorded_at`. A proposed decision dated `9999-12-31` with an otherwise current, valid bootstrap authorization was reproduced on the merged R46 CI wheel: R41 returned READY, R38 returned PASS, and the fresh OperationalMemory projection advanced to year 9999 because decision `recorded_at` is also its event `occurred_at`.

R47 extends the already-merged temporal guard without rewriting historical R38 bytes. After the exact R38 authorization validates, each manifest row must satisfy:

`row.recorded_at <= bootstrap_recorded_at`

This applies to both bootstrap claims and proposed decisions. Historical rows remain valid. Rows recorded exactly at bootstrap authorization time remain valid. A manifest cannot claim that content was recorded after the authority action that approves those exact manifest bytes.

Because R41 and R38 reuse the same `_validate_authorization` boundary, both read-only preflight and effectful bootstrap reject the same invalid manifest before target creation. R40 target-path canonicalization and R46 wall-clock authority sanity remain composed and active.

Regression coverage locks:

- year-9999 proposed decision is rejected by R41 and R38 before target/temp creation;
- year-9999 claim `recorded_at` is rejected before target creation;
- row time equal to `bootstrap_recorded_at` is accepted;
- historical manifest row times remain accepted;
- R40, R46 and R47 markers are simultaneously active on R38.

No new authority, identity-authentication claim, accepted truth, canonical-state mutation, deployment, dispatch, trading, wallet access, or capital permission is introduced.
