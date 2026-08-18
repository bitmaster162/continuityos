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
| KA-21 | Same qualification component is started twice under one protocol/model binding | FAIL before second model call; rerun forbidden |
| KA-22 | Process dies after `R13_COMPONENT_ATTEMPT_STARTED` but before component receipt | Binding remains terminal; no silent retry |
| KA-23 | Sentinel or stable-VOID component returns scientific FAIL | Record `R13_QUALIFICATION_FAILED`; later components and reruns blocked |
| KA-24 | Scientific PASS is appended without exact recorded 2→18→30 component receipts and verified attestation binding | EvidenceStore rejects append |

No test may lower or tune the scientific sentinel relation. No known-answer/mock case is LIVE evidence. A started real qualification component is a point of no return for that exact protocol/model/source binding.

## Engineering authority

Implementation-complete authority is established only by an exact-head green cross-platform review-gates run. This document does not itself authorize model selection, qualification calls, Case #001, merge, deployment, spend, or execution. `valid_live_n=0`; `execution_authority=NONE`.
