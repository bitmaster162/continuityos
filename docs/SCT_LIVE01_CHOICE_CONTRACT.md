# SCT LIVE-0.1 — explicit choice-space contract

## Why this exists

The first prospective LIVE attempt exposed a protocol bug, not a Person Twin result.
The registered options were effectively:

- fix the current preview problem;
- continue SCT/memory work.

Those actions were not mutually exclusive. The human clarified that the real intended
outcome was both actions in parallel. Because the combined outcome was not registered
before prediction commitment, the case was correctly voided as `VOID_CASE_DESIGN`.

LIVE-0.1 prevents that class of error by compiling the real action space into explicit,
mutually exclusive scoreable outcomes before R2 opens the case.

## Modes

### EXCLUSIVE

Use only when outcomes truly exclude one another.

Example:

- APPROVE
- HOLD
- REJECT

### COMBINABLE

Use when more than one action can happen in the same bounded decision window.

Input actions:

- FIX_PREVIEW
- CONTINUE_SCT

Compiled outcomes:

- FIX_PREVIEW
- CONTINUE_SCT
- FIX_PREVIEW+CONTINUE_SCT
- optionally NEITHER

For more than two actions, every non-empty subset is registered. The implementation caps
COMBINABLE mode at four actions so the experiment does not grow a combinatorial beard.

### PRIORITY

Use when the real question is what happens first, rather than whether multiple actions can
happen eventually.

Input actions:

- FIX_PREVIEW
- CONTINUE_SCT

Compiled outcomes:

- FIX_PREVIEW_FIRST
- CONTINUE_SCT_FIRST
- optionally SPLIT

## Integration with R2

R2 still scores one exact registered string. LIVE-0.1 does not change the R2 evidence core.
It compiles concurrent or priority decisions into one exact pre-registered outcome space.

`prepare_contracted_live_case()`:

1. requires an explicit `ChoiceContract`;
2. calls the existing LIVE-0 case builder with the compiled options;
3. writes `choice_contract.json`;
4. injects the same contract into every A/B/C request;
5. writes a hash receipt for the contract and rendered requests;
6. preserves `SHADOW`, `execution_authority=NONE`, and `can_execute=false`.

## Human reveal rule

The human outcome must normalize to one option that existed before predictions were committed.
If the human later clarifies an outcome outside the contract, do not remap it after the fact.
Void the case and fix the next case design instead.

## Status

This is a protocol correction triggered by observed LIVE case-design failure.
It is not SCT-R3, not a memory expansion, and not a claim that SCT predicts better.
