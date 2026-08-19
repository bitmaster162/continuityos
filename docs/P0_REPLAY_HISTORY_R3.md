# P0 Replay History R3

Status: DRAFT CANDIDATE / OFFLINE HISTORY VERIFICATION / NO EFFECT

## Purpose

R1 hardened case and Twin integrity. R2 hardened temporal evidence and externally expected replay anchoring. R3 attacks the history itself:

- old case replayed under a new envelope;
- same case forked to a new binding;
- duplicate human reveal;
- duplicate return;
- event reordering;
- forged previous-head links;
- rollback to an older but internally valid ledger snapshot;
- outcome before reveal;
- return before outcome.

R3 does not create a new authority plane and performs no canonical write.

## Two bounded structures

### 1. Global replay registry snapshot

Schema:

`continuityos.shadow_replay_registry_snapshot.v1`

Each entry binds:

```text
case_id
case_sha256
case_binding_sha256
replay_input_sha256
ledger_id
```

Admission consumes an externally retained `expected_registry_sha256` plus the expected authority-root SHA-256. It rejects:

- same `case_binding_sha256` again -> duplicate replay;
- same case bytes under a different case id -> alias replay;
- same case id with a different case binding -> history fork;
- reused ledger id -> ledger alias/collision.

Successful admission only yields:

`continuityos.shadow_replay_admission_candidate.v1`

with `registry_write_performed=false` and `apply_allowed=false`.

### 2. Per-case append-only ledger snapshot

Schema:

`continuityos.shadow_case_ledger_snapshot.v1`

Canonical P0 event order:

```text
CASE_QUALIFIED
→ TWIN_COMMITTED
→ DECISION_PACKET
→ HUMAN_REVEAL
→ OUTCOME_RECEIPT
→ RETURN_INTAKE
```

Every event binds:

```text
ledger_id
case_id
case_sha256
case_binding_sha256
sequence
previous_event_sha256
event_type
subject_sha256
idempotency_key
recorded_at
```

and receives its own `event_sha256`.

The ledger snapshot itself is hash-bound and must equal an independently expected `expected_ledger_sha256`; its head must equal independently expected `expected_head_event_sha256`.

This blocks rollback to an old but valid snapshot and prevents a locally rehashed fork from silently becoming the accepted history unless the independently retained expected head is also replaced.

## One-case-one-reveal

`HUMAN_REVEAL` is a unique lifecycle event. A second reveal for the same ledger fails closed with:

`one_case_one_reveal_violation`

Likewise only one `RETURN_INTAKE` is accepted in the current P0 lifecycle. A second return fails closed with:

`duplicate_return_intake_detected`

## Ordering invariants

R3 refuses lifecycle regression even when the attacker recomputes all local event and ledger hashes.

Examples:

```text
OUTCOME_RECEIPT before HUMAN_REVEAL -> reject
RETURN_INTAKE before OUTCOME_RECEIPT -> reject
TWIN_COMMITTED after DECISION_PACKET -> reject
reversed event list with rehashed links -> reject
forged previous_event_sha256 -> reject
```

## Authority and write boundary

R3 produces candidates only:

```text
registry_write_performed=false
ledger_write_performed=false
apply_allowed=false
execution_authority=NONE
can_trade=false
capital_permission=DENY
```

A valid candidate is evidence that an append would preserve lineage. It is not the canonical append itself.

## Evidence ceiling

The external expected registry/head digests must be retained by an independently trusted authority/custody surface. Hash chains detect substitution only relative to an expected root/head. If an attacker can rewrite both the complete ledger and the independently retained expected digest, hash equality alone cannot reconstruct authenticity.

R3 ContinuityOS is intentionally domain-generic: `subject_sha256` is a typed content-address field, but ContinuityOS does not itself know whether a `TWIN_COMMITTED`, `DECISION_PACKET`, `HUMAN_REVEAL` or `OUTCOME_RECEIPT` subject is the exact domain artifact expected by TradingOS. That cross-domain subject binding must be verified by the consuming domain/control membrane rather than smuggled into the generic history store.
