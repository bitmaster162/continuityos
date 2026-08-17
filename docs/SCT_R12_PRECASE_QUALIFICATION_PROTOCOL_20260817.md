# SCT R12 — Pre-Case Qualification Amendment

Status: `PROPOSED_IMPLEMENTATION / CASE_001_BLOCKED`
Parent commit: `13256bae2395a514287ccb1685b24b249f087373`
Parent tree: `1393fe4efe2873b27194d628a1325c9b474899dd`
R11 receipt SHA-256: `1c5937da898e89e92d9c9a1f905cb29b8e0aec133fb4fb3dffcfe74a94f1fd0c`
Valid LIVE n at amendment: `0`
Execution authority: `NONE`

## Why R12 exists

R11 is terminal evidence for the current free-provider pool strategy: 20 preregistered VOID
cases, 5 complete and 15 failed, with store verification PASS, zero retries/replacements,
and zero valid LIVE cases. The five completed Nemotron cases also exposed repeated
near-uniform vectors. R12 does not reinterpret R11 as a pass and does not lower R11's
threshold after the fact.

## P0 protocol changes

1. Prediction persistence is versioned as `sct.prediction/v3` and scoring as `sct.score/v2`.
   Top-1 accuracy requires a unique argmax. A tie has no predicted winner and counts as
   incorrect for top-1 accuracy. Full-vector Brier/log-loss remain defined.
2. Confirmatory primary endpoint is paired multiclass Brier skill, C minus B.
   Top-1 accuracy and bounded log-loss are descriptive secondary endpoints.
3. Cluster sign-flip output is a sensitivity calculation under a preregistered
   sign-symmetry/exchangeability assumption, not design-based randomization inference.
4. `n>=100 AND K>=6` is a minimum inference admission floor, not proof of statistical
   power or independence.
5. Probability usefulness is not defined by a post-hoc entropy, confidence, or
   max-minus-min threshold. Honest near-uniform uncertainty is permitted.
6. A synthetic context-responsiveness sentinel must prove that the exact model path
   changes its unique argmax when the only semantically material input change is an
   explicit contradictory synthetic `personal_context`.
7. After the sentinel, a stable single exact model/provider/version must complete a
   preregistered 10–20 case VOID A/B/C run with 3 predictions per case, all cases VOID,
   store verification PASS, no automatic retry, no replacement, and valid LIVE n=0.
8. A genuine operator/provider attestation hash plus an explicit provenance verification
   flag is required for final R12 scientific gate adjudication; a 64-hex string alone is
   not evidence of authenticity.
9. Scientific PASS is persisted as `R12_QUALIFICATION_PASSED` with `case_001_authorized=false`.
   It does not imply enrollment approval.
10. Initial LIVE enrollment requires a separate exact owner token bound to the scientific
    qualification digest. That event is `CASE001_ENROLLMENT_AUTHORIZED`, remains
    `execution_authority=NONE`, and must be recorded before any LIVE case is frozen.
11. The operator CLI exposes `r12 amend`, `context-sentinel`, `stable-void`, `qualify`,
    `status`, and `authorize-case001`. `sct case open` fails closed unless the scientific
    qualification and owner enrollment authorization are both present and hash-bound.

## Operator sequence

1. `sct r12 amend --r11-receipt-sha256 <R11_SHA256>`
2. Run `sct r12 context-sentinel ...` on the chosen stable model/provider path and save the JSON receipt.
3. Run `sct r12 stable-void ...` on the exact same provider/model/version and save the JSON receipt.
4. Verify the genuine operator/provider attestation, then run `sct r12 qualify ... --operator-attestation-verified`.
5. `sct r12 status` must show scientific PASS recorded while LIVE enrollment remains closed.
6. Only after a separate owner decision, record the exact token
   `APPROVE_SCT_CASE001:<qualification_sha256>` through `sct r12 authorize-case001`.
7. Fresh-read Git/repository truth and valid LIVE n before Case #001 enrollment.

## Authority ceiling

Even an R12 scientific PASS does not itself authorize Case #001, merge, deploy, paid
provider spend, or any execution authority. A fresh GitHub/read-back and fresh
`valid_live_n=0` confirmation plus separate owner authorization remain required.
