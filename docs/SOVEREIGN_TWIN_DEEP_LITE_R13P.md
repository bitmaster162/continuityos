# Sovereign Twin DEEP-LITE R13P

## Scope

Product/runtime engineering only. This is **not** the SCT R13 scientific evaluator and does not alter any scientific receipt, Case #001 state, trading permission, or execution authority.

`execution_authority=NONE` and `can_execute=false` remain invariant.

## Why this exists

Local Windows dogfood established two distinct constraints:

1. `qwen3.6-35b-a3b` with 4096 context, parallel=1, Flash Attention and GPU KV cache loaded correctly on a 16 GB RAM / RTX 2060 6 GB laptop, but a DEEP request timed out after about 300 seconds while exhausting almost all RAM/VRAM.
2. `qwen3.5-4b` with public reasoning set to `on` consumed the entire 2200-token output budget as reasoning (`total_output_tokens=2200`, `reasoning_output_tokens=2200`) and produced no final `message`.

LM Studio's model catalog for this Qwen3.5 build exposes only `off` and `on` reasoning options, so `low`/`medium`/`high` cannot be assumed. The public `/api/v1/models/load` contract also does not expose a token-level reasoning budget control.

## Design

DEEP-LITE uses the existing `qwen3.5-4b` model with public reasoning explicitly **off** for both passes:

1. **Draft pass** — same retrieved ContinuityOS evidence, context 4096, max output 400 tokens, temperature 0.15.
2. **Review/final pass** — same evidence plus the first-pass draft marked as untrusted candidate text, context 4096, max output 700 tokens, temperature 0.10.

Only the second-pass text is returned to the user. The first-pass text is not placed in result stats or receipts.

The returned stats contain bounded pass metadata and performance counters only. `reasoning_present=false` by construction.

## Residency and cleanup

Before inference, the runner records whether the target model is already loaded.

- If the model was already resident, DEEP-LITE preserves that residency state.
- If DEEP-LITE caused the load, it best-effort unloads the model after both PASS and FAIL.
- Cleanup failures never replace the primary inference error.

## Local invocation

After installing an exact reviewed source SHA:

```powershell
$py = "$env:LOCALAPPDATA\SovereignTwin\runtime-venv\Scripts\python.exe"
$Db = "$HOME\.continuityos\memory-nomic-768-20260819-223015.db"

& $py -m continuityos.sovereign_twin_deep_lite `
  --db $Db `
  "Using only retrieved ContinuityOS memory, identify one architectural principle, cite mem:<id>, separate memory from inference, and do not execute anything."
```

## Non-goals

- no hidden chain-of-thought exposure;
- no undocumented LM Studio parameters;
- no automatic 35B fallback;
- no execution, tool calls, orders, messages, file mutation, or authority escalation;
- no merge/deploy without separate owner authorization.
