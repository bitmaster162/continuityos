# R13 REQUIRED KNOWN-ANSWER TEST MATRIX

These tests run before any real R13 model call.

| ID | Synthetic runner / condition | Required result |
|---|---|---|
| KA-01 | Context-blind fixed label prior | FAIL sentinel |
| KA-02 | Target-responsive runner plus fixed label prior | PASS if every directed relation holds |
| KA-03 | Runner responds only when canonical label is C | FAIL due balanced mapping |
| KA-04 | Runner follows textual position only | FAIL due order rotations |
| KA-05 | Exact tied target probabilities across contexts | FAIL |
| KA-06 | NaN/Inf allowed-token logit | FAIL |
| KA-07 | Insufficient single-token aliases | Static compatibility FAIL before seal |
| KA-08 | Rationale text changed after probability commit | Probability hash unchanged |
| KA-09 | Arm identity reaches provider/model request | FAIL |
| KA-10 | Automatic retry attempted | FAIL |
| KA-11 | Model/tokenizer/runtime hash drift | FAIL |
| KA-12 | VOID case promoted to LIVE | FAIL |
| KA-13 | Scientific PASS attempts to set execution authority | FAIL |
| KA-14 | Case #001 opens without exact owner token | FAIL |
| KA-15 | Runtime uses/echoes alias token IDs different from sealed model manifest | FAIL |
| KA-16 | Raw allowed-token logits are not captured for a scientific call | FAIL evidence completeness |
| KA-17 | Model or Arm-B template still contains `__FILL__`/`__SHA256__` placeholders | FAIL before seal |
| KA-18 | Operator attestation SHA exists but content/source/receipt binding disagrees | FAIL qualification |
| KA-19 | Arm B baseline lacks frozen builder/retrieval/cutoff/selection hashes | FAIL before seal |
| KA-20 | Legacy JSON prediction runner is used after R13 amendment | FAIL; direct-logit path required |

No test may lower or tune the scientific sentinel relation. No known-answer/mock case is LIVE evidence.
