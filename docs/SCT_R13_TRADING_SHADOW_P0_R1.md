# SCT R13 Trading Shadow P0 R1

Status: DRAFT CANDIDATE / OFFLINE FIXTURE ONLY / NO LIVE CASE / NO ACTION

## Exact baseline

This candidate starts from current SCT R13 branch head:

`944d1711102b7dc12c1be26b17526e87f6b13100`

The R13 scientific qualification, post-PASS hardening and Case #001 owner authorization remain untouched. `valid_live_n=0`; this adapter does not open Case #001 and does not alter the R13 EvidenceStore.

## Purpose

Provide a narrow SCT-side adapter for the unified TradingOS shadow federation.

It accepts a hash-bound `tradingos.shadow_trade_case.v1`, requires `WAIT` among the frozen options, binds the numeric SCT freeze epoch to the timezone-aware TradeCase freeze, and prepares A/B/C contestant inputs only for an offline composition fixture.

The SCT arm is exported as the current `sct.prediction/v3` contract. The export preserves the full prediction hash basis and recomputes `prediction_id` before handing the packet downstream.

## R13 hard boundary

R13 LIVE Arm B provenance hardening is not bypassed.

The adapter has one allowed mode:

`OFFLINE_FIXTURE_ONLY`

Any attempt to use another mode fails closed with:

`TRADING_SHADOW_R13_LIVE_BYPASS_FORBIDDEN`

A mismatched caller-supplied numeric freeze fails closed with:

`TRADING_SHADOW_FREEZE_MISMATCH`

The adapter explicitly records:

```text
store_write_performed=false
live_case_opened=false
live_arm_b_provenance_bypass_allowed=false
execution_authority=NONE
can_execute=false
```

`arena_kwargs=None` is deliberate: this P0 adapter cannot be handed directly to the LIVE arena.

## Prediction integrity

The exported `sct.prediction/v3` keeps:

```text
case_id
arm
options
option_probabilities
predicted_choice
confidence
reasons
change_conditions
would_escalate
committed_at
execution_authority
can_execute
```

`prediction_id` is recomputed from that full body. A stale or tampered id is rejected. This proves internal content integrity only; it is not a source-authenticity signature or custody proof.

## Safety

No model call, EvidenceStore mutation, Case #001 enrollment/open, merge, deploy, runtime registration, order, signal, credential mutation, exchange interaction, trading or capital effect is authorized by this candidate.

The current R13 LIVE path remains governed by its existing frozen provenance builder, qualification binding and prospective admission protocol.

P0 R2 trusted replay adds a stricter separate entrypoint in `sct.trusted_replay`; it does not weaken this R1 boundary.
