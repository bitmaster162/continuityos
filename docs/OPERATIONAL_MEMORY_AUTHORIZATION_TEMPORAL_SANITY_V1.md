# Operational Memory Authorization Temporal Sanity v1 (R46)

R46 closes a temporal-poisoning class in both shadow-memory effect paths:

- R37/R44 existing-memory apply via `apply_recorded_at`;
- R38/R41 fresh project-memory bootstrap via `bootstrap_recorded_at`.

Before R46, those authority timestamps had no upper wall-clock bound. A structurally valid authorization dated `9999-12-31` therefore passed the relevant read-only preflight and the effectful gate. The authority timestamp is reused as durable event/record time, so a successful operation could advance `projection.valid_at` to year 9999 and distort later temporal ordering.

R46 preserves the historical R37 and R38 implementation bytes. A stdlib-only lazy post-import guard wraps their shared authorization-validator boundaries. Because R44 reuses R37 `_validate_authorization` and R41 reuses R38 `_validate_authorization`, the read-only preflights and effectful gates share one temporal policy instead of duplicating it.

The resulting invariant is:

- existing lower-bound and structural validation remains unchanged;
- `apply_recorded_at <= current UTC time + 300 seconds` is required for R37/R44;
- `bootstrap_recorded_at <= current UTC time + 300 seconds` is required for R38/R41.

The five-minute allowance is only clock-skew tolerance. Historical or delayed authorization remains valid when the existing path-specific lower-bound and binding rules still pass. Far-future authority timestamps are rejected during artifact validation, before R44/R41 can report READY and before R37/R38 can perform a write or publish a target database.

The regression suite locks these cases:

- year-9999 apply authorization is rejected by R44 and R37 and the existing DB remains byte-identical;
- year-9999 bootstrap authorization is rejected by R41 and R38 before target/temp creation;
- exactly five minutes of positive apply clock skew is accepted;
- more than five minutes of positive apply clock skew is rejected;
- delayed historical apply authorization remains valid.

No new command, authority class, identity-authentication claim, execution permission, canonical-state mutation, deployment, dispatch, trading, wallet access, or capital permission is introduced.
