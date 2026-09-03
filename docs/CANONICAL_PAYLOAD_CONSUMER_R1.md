# Canonical Payload Consumer R1

`continuity-canon` is a default-disabled, fail-closed, read-only ContinuityOS consumer for the frozen Central Memory canonical payload API at `https://archiveos.bitevo.work`.

## Effect boundary

The consumer permits only HTTPS `GET` reads. It does not write ContinuityOS memory, operational memory, databases, files, provider state, Central Memory, or current state; it does not run subprocesses, deploy, trade, access wallets, or auto-inject into MCP. `context` is an ephemeral in-process projection only.

Any HOLD after an outbound GET has been attempted conservatively reports `network_read=true`, including TLS, transport, JSON, cache-control, and post-response identity/schema validation failures. Pre-network configuration/binding failures remain `network_read=false`.

## Configuration

The feature is disabled unless:

```text
CONTINUITYOS_CANONICAL_PAYLOAD_API_ENABLED=1
CONTINUITYOS_CANONICAL_PAYLOAD_BINDING=/absolute/canonical/path/binding.json
CONTINUITYOS_CANONICAL_PAYLOAD_BINDING_SHA256=<exact sha256>
CONTINUITYOS_CANONICAL_PAYLOAD_PASSWORD=<runtime-only basic-auth password>
```

The password is never persisted or logged. The binding file must be an existing canonical absolute file path, must not be a symlink, and must match the supplied SHA-256 before any network request is attempted.

Binding schema: `CONTINUITYOS_CANONICAL_PAYLOAD_BINDING_V1`. The binding freezes origin/auth identity plus the expected Central Memory source, role, disposition, currentness, digests, counts, project status counts, and `private,no-store` cache-control contract.

## Commands

```text
continuity-canon health
continuity-canon snapshot
continuity-canon decision D001
continuity-canon project continuity-platform
continuity-canon context
```

The five commands are the only `continuity-canon` commands allowed through verified current-session containment. Partial or invalid current-session binding never falls back to the consumer.

`continuity-canon health` verifies both frozen producer health surfaces before accepting readiness:

```text
GET /central-memory/health
GET /central-memory/payload/health
```

The Central canon health response must be `READ_ONLY_READY`, integrity `ok`, source/role/disposition bound, and match the frozen record/projection digests. The payload health response must independently validate the frozen payload meta, 139-decision count, 10-project count, and the same record/projection digests.

## Frozen producer identity

```text
stable_source_id=SRC-MEMORY-CANON-CURRENT
role=CANONICAL_DECISIONS_PROJECTS_GOVERNANCE
resolution_disposition=SELECTED_CURRENT
currentness_status=CURRENT_WITHIN_ROLE
authority_upgraded=false
record_digest=0af4470f1bcd0ba6262d46146aad9e966cd5cc2e9848228d037f6dd798c908dd
projection_digest=5e3fa31d28617ee678ee1af109849493c7153df633c2189b32aabe1dffbb2a76
snapshot_digest=6119e89e09e45b2847de1e1914fa16ab06247f123b7982922a616c4392a2c3fa
decisions=139 contiguous D001-D139, all CURRENT
projects=10 unique: 9 CURRENT_TRUNK + 1 LEGACY_VALID_CONCEPT
```

## Point-ID boundary

Decision IDs must match `^D[0-9]{3}$`; project IDs must match `^[a-z0-9][a-z0-9-]{0,127}$`. Malformed IDs are rejected locally with frozen `422` semantics before any network request, so `/`, `?`, `#`, percent-encoded path separators, whitespace, and other malformed input cannot alter the request target. Valid-but-unknown IDs still reach the producer and preserve `404` semantics.

## Transport hardening

The implementation is stdlib-only and uses `http.client.HTTPSConnection` plus `ssl.create_default_context()`. Host/port are fixed to `archiveos.bitevo.work:443`; redirects are denied; retries are zero; only identity content encoding is accepted; response byte ceilings are enforced; duplicate JSON keys and non-finite constants are rejected. Payload/data responses require both `private` and `no-store` cache-control tokens.

A remote 503 remains a HOLD and does not trigger fallback or a new effect-generating attempt.
