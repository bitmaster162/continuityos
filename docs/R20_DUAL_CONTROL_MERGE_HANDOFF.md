# R20 Dual-Control Merge Handoff

R20 connects the R16–R19 governed-delivery approval chain to the existing R63
merge-authorization control plane without creating a second merge executor.

The handoff is deliberately verification-only:

`R19 MERGE_ELIGIBLE + R63 MERGE_AUTHORIZATION_PASS -> DUAL_CONTROL_MERGE_HANDOFF_READY`

Both control systems must describe the same repository, base branch/head/tree,
candidate branch/head/tree, pull request, and `MERGE_COMMIT` method.

## Trust inputs

R20 re-runs R17 `require_merge_eligibility_current`, so the Ed25519 signature,
registry pin, approval TTL, nested R16 request, and exact current revision remain
authoritative at final handoff time.

The R63 authorization receipt is accepted only when its canonical SHA-256 equals
an externally supplied trusted pin. R20 does not treat a caller-recomputed pin as
independent evidence; custody of that pin remains an operator/control-plane duty.

## Failure model

R20 fails closed on R19 expiry/signature/revision drift, R63 pin mismatch, any
R19/R63 subject disagreement, widened R63 effects, unsupported merge method,
outer receipt tampering, or a re-sealed outer receipt that no longer reconstructs
from the nested authoritative receipts.

The R20 receipt is deterministic and content-addressed. Final validation rebuilds
the receipt from its nested R19 and R63 evidence against the current revision.

## Authority boundary

R20 has no GitHub client, network client, subprocess runner, merge implementation,
deployment path, trading path, wallet access, or capital authority. Its output
keeps `can_merge=false`, `can_execute=false`, `deploy_permission=DENY`,
`can_trade=false`, and `capital_permission=DENY`.

Actual merge execution remains external and must continue to satisfy the existing
R63 merge-execution contract and provider-side expected-head protections. R20 does
not consume or replace that execution gate and does not make distributed-replay
claims beyond the R19 one-host boundary.
