# Operational Memory Authorization Temporal Sanity v1 (R46)

R46 closes a temporal-poisoning defect in the R37/R44 shadow-memory apply path.

Before R46, `apply_recorded_at` was required to be no earlier than the proposal base, but it had no upper bound. A structurally valid authorization dated `9999-12-31` therefore passed R44 preflight and R37 apply. R37 reused that authority timestamp as the durable apply/record time, which could advance `projection.valid_at` to the far future and distort later temporal ordering.

R46 preserves the historical R37 implementation bytes and installs a lazy post-import guard around the shared R37 authorization validator.

The resulting invariant is:

- `apply_recorded_at >= base.valid_at` remains required by R37;
- `apply_recorded_at <= current UTC time + 300 seconds` is additionally required by R46.

The five-minute allowance is only clock-skew tolerance. Historical or delayed authorization remains valid as long as it is not earlier than the exact proposal base. Far-future authority timestamps are rejected before R44 can report READY and before R37 opens the database for a write.

Because R44 reuses R37 `_validate_authorization`, one guard protects both paths without adding a second temporal policy implementation.

The regression suite locks four cases:

- year-9999 authorization is rejected by R44 and R37 and the DB remains byte-identical;
- exactly five minutes of positive skew is accepted;
- more than five minutes of positive skew is rejected;
- delayed historical authorization remains valid.

No new command, authority class, authentication claim, execution permission, canonical-state mutation, deployment, dispatch, trading, wallet access, or capital permission is introduced.
