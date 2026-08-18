# Implementation scope

Only these code deltas are authorized on this branch:

1. Canonicalize CLI component receipt wrappers back to the exact immutable core receipt before qualification binding, rejecting any non-wrapper mutation.
2. Bind LIVE Arm B contestant input to the frozen deterministic Arm B builder and source-cutoff/admitted-pool provenance before CASE_FROZEN.
3. Add adversarial regression tests for direct CLI/Python/store bypasses.

No scientific model call, rerun, Case #001, owner authorization, merge, deploy, spend, or execution authority change is authorized.
