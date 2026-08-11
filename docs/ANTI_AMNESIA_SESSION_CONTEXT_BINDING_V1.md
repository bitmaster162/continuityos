# Anti-Amnesia Session Context Acknowledgement v1

## Purpose

Cold-start v1 proves that a fresh model recovered the controller-authored
session capsule. Common Operational Context v1 proves that a bounded memory
projection was generated from a named checkpoint. Session Input Manifest v1
then binds the capsule, context, controller selection spec and the exact
successful context-verification receipt.

Session Context Acknowledgement v1 adds one final delivery proof without
changing those canonical artifacts:

```text
R63 boot receipt
  -> cold-start session capsule
  -> bounded operational context
  -> OPERATIONAL_CONTEXT_VERIFY_PASS receipt
  -> canonical SESSION_INPUT_MANIFEST
  -> candidate delivery envelope
  -> exact SESSION_CONTEXT_ACK
```

The model receives the capsule, context, canonical input manifest, a compact
binding envelope, strict ACK schema and minimal instructions. The controller
retains the base challenge, context spec, context-verification receipt and hidden
expected acknowledgement.

The acknowledgement never means content acceptance or state application:

```text
accepted_truth_owner = CONTROL_CENTER
content_acceptance    = NOT_PERFORMED
state_apply           = DISABLED
can_trade             = false
capital_permission    = DENY
```

## Prepare

Prerequisites:

1. A verified `COLD_START_CHALLENGE.json` and controller-pinned SHA-256.
2. A canonical `CONTINUITYOS_OPERATIONAL_CONTEXT_PACK_V1`.
3. Its controller-authored `OPERATIONAL_CONTEXT_SPEC.json`.
4. An exact `OPERATIONAL_CONTEXT_VERIFY_PASS` receipt.
5. A canonical `ANTI_AMNESIA_SESSION_INPUT_MANIFEST_V1`, verified byte-for-byte
   against all four artifacts above.

```powershell
continuity cold-start bind-context `
  --challenge COLD_START_CHALLENGE.json `
  --challenge-sha256 <PINNED_CHALLENGE_SHA256> `
  --context OPERATIONAL_CONTEXT.json `
  --manifest SESSION_INPUT_MANIFEST.json `
  --manifest-sha256 <PINNED_MANIFEST_FILE_SHA256> `
  --context-spec OPERATIONAL_CONTEXT_SPEC.json `
  --context-verification OPERATIONAL_CONTEXT_VERIFY_RECEIPT.json `
  --output SESSION_CONTEXT_CHALLENGE
```

Candidate-facing files:

```text
candidate/
  SESSION_CAPSULE.json
  OPERATIONAL_CONTEXT.json
  SESSION_INPUT_MANIFEST.json
  SESSION_CONTEXT_BINDING.json
  SESSION_CONTEXT_ACK.schema.json
  INSTRUCTIONS.md
```

Controller-only files:

```text
controller/
  BASE_COLD_START_CHALLENGE.json
  OPERATIONAL_CONTEXT_SPEC.json
  OPERATIONAL_CONTEXT_VERIFY_RECEIPT.json
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

- the pinned delivery challenge SHA-256;
- the copied base cold-start challenge;
- the canonical session-input manifest and its pinned file SHA-256;
- byte-for-byte manifest reconstruction from capsule, context, selection spec
  and context-verification receipt;
- capsule/context/checkpoint/replay-cursor/projection relationships;
- the exact candidate schema and instructions;
- every acknowledgement field and all permission ceilings.

Any extra field, mismatch, tamper, forged verification receipt, wrong checkpoint,
wrong capsule or permission escalation returns `SESSION_CONTEXT_FAIL` with
`release_blocked=true`.

## Non-goals

- no content acceptance;
- no state apply;
- no R63 mutation;
- no operational database write;
- no Git write or deployment;
- no claim that the model used every context item in hidden reasoning.

The next gated layer is semantic-close v1.2: a return must cite the exact session
input manifest, delivery challenge and successful context acknowledgement.
