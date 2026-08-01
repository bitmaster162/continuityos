# Anti-Amnesia Session Context Binding v1

## Purpose

Cold-start v1 proves that a fresh model recovered the exact controller-authored
session capsule. Common Operational Context v1 proves that a bounded memory
projection was generated from a named checkpoint. Session Context Binding v1
binds those two artifacts into one read-only session contract without changing
the base capsule or creating a circular hash dependency.

```text
R63 boot receipt
  -> cold-start session capsule
  -> bounded operational context (bound to capsule SHA-256)
  -> session-context binding manifest
  -> exact SESSION_CONTEXT_ACK
```

The binding does not claim that context content is accepted truth. It preserves:

```text
accepted_truth_owner = CONTROL_CENTER
content_acceptance    = NOT_PERFORMED
state_apply           = DISABLED
can_trade             = false
capital_permission    = DENY
```

## Prepare

Prerequisites:

1. A verified `COLD_START_CHALLENGE.json` and pinned SHA-256.
2. A verified `CONTINUITYOS_OPERATIONAL_CONTEXT_PACK_V1` generated from the
   challenge's exact `SESSION_CAPSULE.json`.

```powershell
continuity cold-start bind-context `
  --challenge COLD_START_CHALLENGE.json `
  --challenge-sha256 <PINNED_SHA256> `
  --context OPERATIONAL_CONTEXT.json `
  --output SESSION_CONTEXT_CHALLENGE
```

Candidate-facing files:

```text
candidate/
  SESSION_CAPSULE.json
  OPERATIONAL_CONTEXT.json
  SESSION_CONTEXT_BINDING.json
  SESSION_CONTEXT_ACK.schema.json
  INSTRUCTIONS.md
```

Controller-only files:

```text
controller/
  BASE_COLD_START_CHALLENGE.json
  EXPECTED_SESSION_CONTEXT_ACK.json
```

## Verify

A fresh model receives only the candidate-facing files and returns exactly one
`SESSION_CONTEXT_ACK.json`.

```powershell
continuity cold-start verify-context `
  --challenge SESSION_CONTEXT_CHALLENGE.json `
  --challenge-sha256 <PINNED_SHA256> `
  --ack SESSION_CONTEXT_ACK.json
```

The verifier rechecks:

- the pinned challenge SHA-256;
- the copied base challenge identity;
- capsule, context, schema and instruction hashes;
- the context pack self-hash;
- capsule-to-context session binding;
- checkpoint, cursor, projection and selection-spec binding;
- exact acknowledgement fields;
- all read-only and permission ceilings.

Any extra field, mismatch, tamper, wrong checkpoint, wrong capsule or permission
escalation returns `SESSION_CONTEXT_FAIL` with `release_blocked=true`.

## Non-goals

- no content acceptance;
- no state apply;
- no R63 mutation;
- no operational database write;
- no Git write or deployment;
- no proof that a model used the context in every internal reasoning step.

The last point is addressed later by binding the verified session-context
challenge and acknowledgement into semantic close.
