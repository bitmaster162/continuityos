# SCT Case #001 owner gate after R13 PASS

R13 scientific PASS does not authorize Case #001.

Current qualification SHA-256:
`fe64f44570486e9971d451776085c64ac742a0b490f9c43a4d4af73084d02af2`

The exact future owner token remains:

`APPROVE_SCT_CASE001_R13:fe64f44570486e9971d451776085c64ac742a0b490f9c43a4d4af73084d02af2`

This document records the required token form only. It is not an authorization event and must never be interpreted as owner approval.

Before the token may be accepted:
- LIVE Arm B provenance hardening must be complete and CI-verified;
- Case #001 must still have `valid_live_n=0` before opening;
- `execution_authority=NONE` and `can_execute=false` remain invariant.
