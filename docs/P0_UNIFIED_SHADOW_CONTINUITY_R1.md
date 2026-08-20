# P0 Unified Shadow Continuity R1

Status: DRAFT CANDIDATE / READ-ONLY / NO EFFECT

## Purpose

This slice gives modern ContinuityOS an explicit role in the BitEvo 63-node P0 shadow transaction without confusing three different evidence dimensions:

1. modern GitHub product/source identity;
2. historical local adoption/runtime-preflight evidence;
3. current live host/runtime state.

They are not interchangeable.

## Fresh modern source baseline

This candidate branch was created from the protected `bitmaster162/continuityos` `master` head:

`9dfb9e5b847a27113ca7c709a0adee900e3ff63f`

Claim ceiling:

`MODERN_GITHUB_SOURCE_ONLY`

A repository HEAD proves source identity. It does not prove runtime activation, deployment, current host state, or effect authority.

## Historical evidence is preserved separately

### R52

Historical local code-root adoption:

- local HEAD: `b5436f373dcb19873a3b0908b26f8d0e22cb8125`;
- terminal: `LOCAL_CANONICAL_ADOPTION_PASS`;
- claim ceiling: `LOCAL_CONTROL_LIBRARY_ADOPTION_ONLY`.

This SHA is not treated as the modern GitHub `master` identity and does not prove current runtime.

### R57

Later runtime-adoption preflight:

- strict-return ZIP SHA-256: `187b0723de9290159da96fc45357a58acf7d177aea7d65eaecc094ef4a17521e`;
- terminal: `REVISE`;
- claim ceiling: `PREFLIGHT_ONLY`.

Therefore R52 must not be promoted into a live-runtime claim. Current live host state remains:

`UNVERIFIED`

## Transaction role

The adapter consumes one hash-bound:

`bitevo.unified_shadow_transaction.v2`

and returns:

`continuityos.shadow_continuity_receipt.v1`

It validates:

- exact transaction self-hash;
- exact 63-node registry count;
- SHADOW / NONE / false / DENY safety vector;
- every effect-boundary field remains false;
- `HOLD => WAIT`;
- stale authority evidence cannot pass the control gate;
- attention cannot pass the control gate;
- exact modern ContinuityOS source HEAD.

## Candidate artifacts, not canonical writes

The receipt derives three deterministic hash-bound candidates:

```text
shadow_checkpoint_candidate
        ↓
shadow_replay_candidate
        ↓
shadow_return_candidate
```

All three remain candidate/read-only objects.

The following are fixed false:

```text
event_append
memory_write
checkpoint_write
replay_write
return_broker_write
archive_write
runtime_activation
pointer_update
```

The Return candidate also carries:

`semantic_acceptance=NOT_PERFORMED`

because transport/indexing is not semantic acceptance.

## Authority boundary

```text
model output
!= evidence
!= memory
!= current truth
!= authority
!= permission
!= effect
```

The receipt grants no authority:

```text
execution_authority=NONE
apply_authorized=false
can_trade=false
capital_permission=DENY
```

Any future canonical memory/checkpoint/Return/runtime application requires a separate current source read, explicit authority, preflight, atomic apply and durable receipt. P0 does none of those steps.
