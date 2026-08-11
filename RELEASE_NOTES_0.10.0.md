# ContinuityOS 0.10.0 — Release Candidate Notes

Status: **release candidate; not tagged or published**.

This release turns the existing ContinuityOS memory/continuity stack into a clearer product workflow for switching AI sessions and MCP-capable clients without rebuilding context by hand.

## Product workflow

```bash
pip install continuityos
cos setup
cos import <export-path> --extract
cos connect <client> --dry-run
cos connect <client> --yes
cos status
cos demo continuity
cos boot
```

## New product surfaces

### `cos connect`

Safe MCP onboarding for Claude and Cursor, with guidance for Hermes and generic MCP clients.

Managed configuration includes:

- exact memory DB binding;
- preview / `--dry-run` before write;
- preservation of unrelated client configuration;
- backup and rollback state;
- drift detection between preview and write;
- MCP `initialize` verification;
- automatic rollback when verification fails.

### `cos status`

Read-only product health surface covering durable memory, continuity state, checkpoints/open loops and configured client state. SQLite inspection is fail-closed: active WAL/journal state returns HOLD/BUSY rather than presenting a potentially stale snapshot.

### `cos demo continuity`

Self-contained proof of the core product promise:

```text
write isolated temporary state
-> close writer
-> open a separate Python process
-> recover fact + canon + frontiers + loop + checkpoint + next action
-> rebuild handoff + verify doctor
-> clean temporary state
-> PASS / FAIL
```

The demo does not resolve, read or write the user's normal ContinuityOS memory DB and does not call an external model or network service.

## Discoverability

`cos --help` is now product-first and exposes the v0.10 workflow. `cos --version` reports the canonical package version.

Both surfaces remain behind the same current-session containment used by product and legacy commands. A verified R64 READ_ONLY session HOLDs instead of allowing help/version/product commands to become an escape hatch.

## Documentation and metadata

- README quick start now leads with setup/import/connect/status/demo/boot.
- MCP guide uses `cos connect` as the recommended path.
- Cursor manual fallback uses `mcpServers`.
- MCP tool inventory is defined by the live `tools/list` response rather than a stale fixed count.
- package description reflects durable memory + cross-session continuity + MCP onboarding.

## Compatibility

- Python 3.10+
- stdlib-only core remains supported
- optional embedding extras remain unchanged
- canonical `cos = continuityos.current_entrypoints:cos_main` entrypoint remains unchanged

## Release boundary

This RC does **not** authorize or perform:

- creation of tag `v0.10.0`;
- GitHub Release publication;
- PyPI publication;
- deployment;
- agent dispatch;
- trading, wallet or capital effects.

The existing publish workflow triggers on `v*` tags, so tag creation is an explicit release effect and requires separate authorization after RC merge and final readback.
