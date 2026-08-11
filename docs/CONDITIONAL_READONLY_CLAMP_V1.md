# Conditional Acceptance Read-Only Clamp v1

R21 closes an authority-widening gap in state-bound cold-start.

A resolved `PASS_WITH_CONDITIONS` is operational acceptance, not unrestricted
permission. Therefore `continuity-state prepare-cold-start` now permits conditional
acceptance only when the cold-start spec requests exactly:

`effect_ceiling = READ_ONLY`

Any wider effect ceiling is a fail-closed HOLD before the cold-start preparer is
called and before the final output path is created.

For a full resolved `PASS`, the existing cold-start effect-ceiling rules remain in
force; R21 does not invent new deployment, trading, capital, memory, messaging, or
self-application authority.

## Exact spec binding

The wrapper reads and hashes the requested spec, prepares the legacy challenge in a
temporary sibling path, and checks that the generated `COLD_START_CHALLENGE.json`
contains the exact same `session_spec.sha256`. Only after that proof does the wrapper
atomically publish the requested final output directory.

If the spec changes between precheck and challenge construction, the temporary
challenge is deleted and the command returns `STATE_BOUND_COLD_START_REVISE`.

This preserves the historical R63 cold-start schema while preventing both effect
widening under conditional acceptance and spec-byte substitution during preparation.
