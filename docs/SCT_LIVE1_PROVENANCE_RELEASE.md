# SCT LIVE-1 — Provenance Release Gate

LIVE-1 is a generic public-code release layer above the existing LIVE-0.1 choice
contract and LIVE-0 TwinBench bridge.

It deliberately does **not** contain principal-specific Person Twin data, raw
conversation excerpts, message IDs, file paths, or direct-source evidence.

## Required chain

1. A private evidence process adjudicates the configured core feature thresholds.
2. `build_feature_release()` creates a privacy-minimized release object containing only
   feature ID, admission state, gate result, decision count, cluster count, strength,
   and the hash of the private parent evidence package.
3. `build_opportunity()` freezes a genuinely unresolved, uncontaminated prospective
   opportunity before prediction/reveal.
4. Existing LIVE-0.1 compiles the explicit scoreable choice contract.
5. `prepare_released_live_case()` binds the feature release, opportunity, choice
   contract, and exact A/B/C frozen input snapshot hashes into one release receipt.
6. Existing TwinBench prediction commit/reveal/scoring continues unchanged.

## Fail-closed requirements

Default core provenance thresholds are:

- `DS-001`: at least 3 direct-source decisions across at least 2 independent clusters.
- `DS-002`: at least 2 direct-source decisions across at least 2 independent clusters.

Both must be `PROVENANCE_ADMITTED_PROVISIONAL`, have `gate_met=true`, and positive
predictive strength.

The prospective opportunity is rejected if the human inclination was already disclosed,
an assistant recommendation contaminated the choice, the actual choice is already known,
the case is retrospective, or it is in an excluded high-stakes domain.

## Privacy boundary

The public repository receives only the release hash and aggregate admission metadata.
Raw provenance remains private/out-of-repository.

## Authority boundary

All release objects and receipts are `SHADOW`, `execution_authority=NONE`,
`can_execute=false`.

Prediction does not grant permission or execution authority.

## Compatibility

LIVE-0 and LIVE-0.1 remain available for historical/debug compatibility. Epoch-style
prospective evaluation that claims provenance-gated LIVE status should use LIVE-1.

This layer does not call provider APIs. A/B/C model execution remains external and must
use the same frozen provider/model/version/settings contract already required by
`live_twinbench.py`.
