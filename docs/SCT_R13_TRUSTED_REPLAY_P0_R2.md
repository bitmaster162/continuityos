# SCT R13 Trusted Replay P0 R2

Status: `DRAFT CANDIDATE / OFFLINE TRUSTED REPLAY ONLY / NO LIVE CASE / NO ACTION`

## Purpose

R2 adds an SCT entrypoint that refuses to treat a raw replay artifact as trusted merely because its internal hashes are self-consistent.

Upstream TradingOS P0 R2 performs the temporal-evidence and external-root checks and emits:

```text
tradingos.shadow_temporal_replay_qualification.v1
        ↓
tradingos.trusted_replay_input.v1
```

SCT consumes that wrapper only when the caller also supplies the exact expected `qualification_sha256` retained outside the replay artifact.

## Boundary

The SCT adapter validates:

- exact replay-input self hash;
- exact TradeCase content hash and case binding;
- exact qualification self hash;
- `qualification_sha256 == externally expected qualification SHA-256`;
- qualified temporal/trust status;
- all replay and qualification effects remain false;
- no source-authenticity claim is created inside SCT.

It then delegates to the existing `OFFLINE_FIXTURE_ONLY` Trading shadow preparation and binds these fields into a new SCT preparation receipt:

```text
trade_case_sha256
qualification_sha256
replay_input_sha256
base_preparation_sha256
input_snapshot_sha256
```

The new receipt schema is:

`sct.trusted_replay_shadow_preparation.v1`

## Why expected qualification hash is external

A self-hash detects accidental or local tampering but cannot establish authenticity when an attacker can rewrite the entire artifact and recompute every digest.

Therefore SCT does not decide that a replay qualification is trusted.

The exact expected qualification digest must come from an independently retained Control Center / ContinuityOS / custody / signed-manifest reference. SCT only verifies equality and binds it into preparation.

```text
hash integrity != authenticity
SCT verification != trust-root ownership
qualification != execution permission
```

## R13 boundary unchanged

This path remains offline only:

```text
store_write_performed=false
live_case_opened=false
live_arm_b_provenance_bypass_allowed=false
execution_authority=NONE
can_execute=false
arena_kwargs=None
```

It does not open Case #001, write EvidenceStore, call a model, register runtime, send signals/orders, or change capital permissions.

`valid_live_n=0` remains unchanged by this P0 adapter.
