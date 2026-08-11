# Anti-Amnesia Cold-Start Test v1

The cold-start test measures whether a fresh agent session can recover the
material execution state from one controller-generated capsule without using
chat history, the full archive, or hidden memory.

It is not a memory benchmark and it does not invoke an LLM. ContinuityOS only
prepares the challenge and verifies one structured `BOOT_ACK.json` exactly.

## Prepare

Inputs:

- a schema-valid `ANTI_AMNESIA_BOOT_RECEIPT_V1` that is not held;
- a controller-authored `ANTI_AMNESIA_COLD_START_SPEC_V1`;
- a new output directory that does not already exist.

```powershell
continuity cold-start prepare `
  --boot-receipt .\BOOT_RECEIPT.json `
  --spec .\COLD_START_SPEC.json `
  --output .\cold_start_challenge
```

The command writes atomically:

```text
cold_start_challenge/
├── COLD_START_CHALLENGE.json
├── SHA256SUMS.txt
├── candidate/
│   └── SESSION_CAPSULE.json
└── controller/
    └── EXPECTED_BOOT_ACK.json
```

Only `candidate/SESSION_CAPSULE.json` is given to the fresh agent. The challenge
and expected ack remain controller-side.

## Agent output

The fresh session must return exactly one `BOOT_ACK.json` using schema
`ANTI_AMNESIA_BOOT_ACK_V1`. Extra fields, prose, changed list order, missing
items, or different values fail the test.

The ack covers:

- authority generation;
- role and active case;
- work-order identity;
- Git baseline HEAD/tree;
- allowed and forbidden changes;
- immutable decisions;
- next action and terminal condition;
- effect ceiling;
- Codex-dispatch and trading permissions;
- boot status and warnings.

## Verify

The controller must pin the challenge SHA-256 from the prepare receipt:

```powershell
continuity cold-start verify `
  --challenge .\cold_start_challenge\COLD_START_CHALLENGE.json `
  --challenge-sha256 <SHA256_FROM_PREPARE_RECEIPT> `
  --ack .\BOOT_ACK.json
```

Possible results:

```text
COLD_START_PASS
COLD_START_FAIL
```

Any mismatch sets `release_blocked=true`.

## Security and effect boundary

- The candidate never receives the hidden expected ack.
- The challenge hash is controller-pinned during verification.
- Prepare refuses existing output directories and publishes by atomic rename.
- Challenge-relative paths reject traversal and symlinks/reparse points.
- No repository, R63, runtime state, checkpoint, service, deployment, trade, or
  capital state is modified.
- A pass proves structured continuity for the supplied capsule only. It does not
  authorize live installation or state application.
