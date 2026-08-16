# SCT LIVE-0 — Pre-live TwinBench bridge

## Status

LIVE-0 is the smallest bridge from the already-merged R1/R2 evidence harness to a real
prospective decision case. It is **not SCT-R3** and it does not approve any new memory,
training, delegation, or execution architecture.

The target experiment is:

```text
real prospective decision
→ freeze one common model manifest
→ freeze A/B/C contestant inputs
→ register their SHA-256 snapshots in R2
→ run each contestant exactly once
→ commit all predictions
→ only then reveal the human choice
→ score and preserve the wrong predictions
```

## Contestants

LIVE-0 registers exactly three required baselines:

- `generic`: scenario + options only, no personal context;
- `profile_rag`: approved static profile + explicitly permitted frozen history;
- `sct`: frozen sovereign person state available before the decision.

`build_standard_inputs()` intentionally holds provider, model, model version, token budget,
temperature and reasoning settings constant across all three contestants. The variable under test
is the personalization context, not which vendor happened to be smarter that afternoon.

## Case eligibility

A case is admitted only when it is prospective, discrete or rankable, unseen before registration,
registered before human commitment, non-trivial, resolvable in the study window, and not fully
forced by external circumstances.

`CaseEligibility` is a pre-registration guard, not a claim that the resulting case is scientifically
perfect. Ambiguous or later-reversed human decisions should be handled according to the study
protocol rather than silently relabelled after seeing model predictions.

## Frozen evidence bundle

`prepare_live_case()` writes a local bundle:

```text
<root>/<case_id>/
  case_manifest.json
  inputs/
    generic.json
    profile_rag.json
    sct.json
  requests/
    generic.json
    profile_rag.json
    sct.json
```

Every contestant snapshot includes its full system prompt, permitted context, provider/model
manifest and inference settings. Its `snapshot_sha256` is registered in the R2 arena before any
prediction can count.

The request files are provider-neutral. LIVE-0 does not ship API clients or credentials. A caller
may execute those request packages with GPT, Claude, Gemini, an open-weight model or a separate
runner, but the returned prediction must be committed to the same R2 case exactly once.

**Operational note:** these live bundles may contain sensitive personal context. Store them in a
private runtime path or another access-controlled location. Do not commit real live-case bundles
into the public repository.

## Response contract

Each contestant returns:

```json
{
  "predicted_choice": "one exact option",
  "confidence": 0.0,
  "reasons": ["short evidence-grounded reason"],
  "change_conditions": ["what new evidence could change the prediction"],
  "would_escalate": false
}
```

R2 remains the authority for commit-before-reveal, duplicate prevention, one shared human outcome,
score calculation, pairwise comparison and ledger verification.

## Minimal Live Case #001 flow

```python
from continuityos.live_twinbench import build_standard_inputs, prepare_live_case
from continuityos.twinbench import TwinBenchArena

arena = TwinBenchArena("/private/sct-live/arena.jsonl")
inputs = build_standard_inputs(
    provider="YOUR_PROVIDER",
    model="YOUR_MODEL",
    model_version="PINNED_VERSION",
    static_profile="APPROVED STATIC PROFILE",
    permitted_history="FROZEN PERMITTED HISTORY",
    sct_state="FROZEN SOVEREIGN PERSON STATE",
)

prepare_live_case(
    arena,
    root="/private/sct-live/cases",
    case_id="live-001",
    decision_surface="executive_inbox_triage",
    situation="...",
    options=["OPTION_A", "OPTION_B"],
    frozen_inputs=inputs,
)
```

Then run the three generated request packages once, commit each response with
`arena.submit_prediction(...)`, reveal the actual human answer only after all three commits with
`arena.reveal_human(...)`, and call `arena.finalize_case(...)`.

## Evidence export

`analysis_export()` exposes R2 leaderboard and pairwise evidence while adding conservative workflow
labels:

- `<20`: `DEBUG_ONLY`;
- `20–29`: `PILOT_NO_CLAIM`;
- `30–99`: `DIRECTIONAL_ONLY`;
- `>=100`: `DEFENSIBLE_DIRECTIONAL_CANDIDATE`.

These are **workflow labels, not statistical proof**. Effect size, paired comparisons, confidence
intervals and the pre-registered analysis still determine what may be claimed.

The primary comparison is `sct` vs `profile_rag`; generic is the zero-personalization baseline.

## Explicit non-goals

LIVE-0 does not add:

- temporal knowledge graphs;
- A-MAC / ConsistencyGate / MemRouter / SMSR;
- active elicitation;
- LoRA, SFT or continual training;
- UCAN / DID / PKI;
- delegated execution;
- avatars or voice;
- a new foundation model;
- automatic canon, policy or grant mutation.

Those remain evidence-triggered future work. The next milestone after merge is **Live Case #001 and
prospective data**, not another architecture layer.
