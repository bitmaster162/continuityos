# Anti-Amnesia Semantic Close v1.2 — Verified Read-Only Return Binding

## Purpose

Semantic close v1.1 binds a return to the current R63 boot receipt, a controller
work-order body, a role permission policy, technical evidence and an optional
Git/delta proof.

Semantic close v1.2 additionally proves which verified session input chain was
used before the work began:

```text
R63 boot
  -> SESSION_CAPSULE
  -> bounded OPERATIONAL_CONTEXT
  -> SESSION_INPUT_MANIFEST
  -> SESSION_CONTEXT_CHALLENGE
  -> exact SESSION_CONTEXT_ACK
  -> controller SESSION_CONTEXT_PASS verdict
  -> read-only task return
  -> semantic close v1.2 receipt
```

This prevents a task result from being written back into immutable boot state.
`BOOT_ACK` remains a statement of what the agent received at startup. Task
outcomes belong in the return envelope and close receipt.

## Current effect ceiling

Common Operational Context v1 is explicitly `READ_ONLY`. Semantic close v1.2
therefore accepts only read-only work classes:

- `RESEARCH`
- `AUDIT`
- `TRANSPORT`
- `CONTENT`
- `OTHER`

It rejects:

- `IMPLEMENTATION` task class;
- any proposed state delta;
- any Git mutation proof;
- any requested live/external effect;
- any trading, capital, deployment or self-application permission.

A reversible-write session contract requires a separate future version. The
read-only ceiling is not widened implicitly.

## Return envelope

The return package contains one canonical:

```text
ANTI_AMNESIA_RETURN_V1_2.json
```

It wraps an exact v1.1 semantic return and binds controller-pinned session
artifacts:

```json
{
  "schema": "ANTI_AMNESIA_RETURN_V1_2",
  "gate": "ANTI_AMNESIA_GATE_V1",
  "mode": "SHADOW",
  "semantic_return_v1_1": {},
  "session_context_binding": {
    "session_input_manifest_file_sha256": "...",
    "session_input_manifest_sha256": "...",
    "session_context_binding_id": "...",
    "session_context_challenge_sha256": "...",
    "session_context_ack_sha256": "...",
    "session_context_verdict_sha256": "...",
    "session_context_verdict_status": "SESSION_CONTEXT_PASS"
  }
}
```

The nested v1.1 envelope remains subject to its own strict schema and runtime
validator. The v1.2 top-level schema is not a replacement for the v1.1 schema.

## CLI

```powershell
continuity close `
  --return RETURN_DIR_OR_ZIP `
  --dry-run `
  --work-order WORK_ORDER.md `
  --permission-policy ROLE_PERMISSION_POLICY.json `
  --session-input-manifest SESSION_INPUT_MANIFEST.json `
  --session-input-manifest-sha256 <SHA256> `
  --session-context-challenge SESSION_CONTEXT_CHALLENGE.json `
  --session-context-challenge-sha256 <SHA256> `
  --session-context-ack SESSION_CONTEXT_ACK.json `
  --session-context-verdict SESSION_CONTEXT_VERDICT.json `
  --session-context-verdict-sha256 <SHA256> `
  --control-root <R63_ROOT> `
  --workspace-root <CONTINUITYOS_ROOT>
```

## Controller verification

The controller independently:

1. validates the v1.2 envelope and read-only ceiling;
2. constructs a normalized v1.1 return view and runs semantic close v1.1;
3. validates the pinned canonical session-input manifest and self-hash;
4. verifies that the exact manifest is the one named by the challenge;
5. replays the session-context challenge against the exact ACK;
6. reconstructs the exact `SESSION_CONTEXT_PASS` verdict;
7. byte-compares the provided verdict with the reconstructed verdict;
8. matches role, case, work-order ID, pointer SHA and workspace digest between
   the manifest and the v1.1 return;
9. preserves all DENY/false ceilings.

Any mismatch returns:

```text
WOULD_HOLD
SHADOW_HOLD
```

## Non-goals

- no state application;
- no R63 mutation;
- no operational-memory write;
- no Git write or merge;
- no deployment;
- no trading or capital permission;
- no claim that a model used every context item in hidden reasoning.
