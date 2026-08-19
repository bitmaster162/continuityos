# SCT Trading Shadow Adapter — P0 R1

Status: CANDIDATE BRANCH ONLY / SHADOW / NO ACTION

Baseline: `13256bae2395a514287ccb1685b24b249f087373` from `agent/sct-epoch001-amendment-v2`.

## Purpose

Adapt a hash-bound `tradingos.shadow_trade_case.v1` into the existing SCT A/B/C prediction envelope without changing SCT authority semantics.

`prepare_trading_shadow_case()` is pure preparation. It performs no EvidenceStore write, no provider call and no arena enrollment. It returns explicit `arena_kwargs` for a later separately authorized prospective run.

`export_sct_prediction()` only accepts the committed `arm=sct` prediction contract and preserves:

```text
execution_authority=NONE
can_execute=false
```

## Boundary

SCT predicts the human trade action. It does not judge market quality and it does not grant trading authority. TradingOS remains the domain decision layer; TRIAXIS remains an independent adversarial audit layer.

No Case #001 is created by this adapter and the current SCT LIVE count is not modified by this candidate-branch change.
