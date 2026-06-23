# Changelog

All notable changes to **ContinuityOS** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

ContinuityOS is a local-first, MCP-native **durable memory + continuity + governance**
layer for AI agents and humans. Core is stdlib-only, stores everything in one SQLite
file, and runs with zero external services. Apache-2.0.

## [Unreleased]

### v0.7.1 — DevOps integration fixes

Focus: making v0.7.0 survive daily, unsupervised operation inside a real agent
workflow (Hermes), with safer storage and better recall out of the box.

### Added
- **Hermes shell hooks** — `gate_hook.py` enforces the Gate preflight on every
  shell action the agent attempts (`continuity run shell`), so dangerous commands
  are blocked at the boundary instead of just logged.
- **`mcp_bridge.py` + `mcp_bridge.bat`** — cross-platform Python bridge so the MCP
  server launches reliably from `.bat`/Windows shells as well as POSIX ones.
- **Backup cron** — daily `backups/` snapshots of `hermes_memory.db`
  (e.g. `hermes_memory_20260624_034959.db`).
- **`CANONICAL_TRUTH.md`** — documents the single source-of-truth policy across the
  three parallel memory stores (ContinuityOS Memory DB / Hermes MEMORY+USER /
  OS Runtime `state.json`) and the conflict-resolution rules.

### Changed
- **Embeddings: FastEmbed `bge-small-en` upgrade** — default real-embedder model
  bumped; recall improved **0.40 → 0.79** on the recall bench.
- **CLI & MCP auto-detect FastEmbed with fallback** — both the `cos` CLI and the
  MCP server now try the FastEmbed embedder first and transparently fall back to the
  offline `HashingEmbedder` if it is unavailable, so install is still zero-dep.
- **SQLite WAL mode** enabled by default for concurrent read/write safety.

### Fixed
- All five "devil's advocate" audit findings (`169519d`).
- Remaining audit items #3, #4, #6, #13 (`aea5d19`) across `cli.py` and
  `mcp_server.py`.

---

## [0.7.0] — 2026-06-24

First tagged **full-system snapshot** (`5a43587`). Brings together the six
layers — memory, continuity, council, twin, control plane, autopoiesis — plus a
governance Gate, MCP server, CLI, HTTP API, and Docker packaging.

### Added
- **Memory** — hybrid (structural + semantic) recall over a single SQLite file:
  FTS5 keyword index + vector store, folder-like namespaces, tags, and a `context()`
  injector for agent prompts.
- **Continuity** — canon rules, frontiers, open loops, checkpoints, an anti-drift
  "doctor", and handoff packs that carry the thread between sessions and model versions.
- **Gate** — AI-agent governance gateway. Every risky shell/file/git action gets a
  preflight decision — `ALLOW · WARN · HOLD · DENY · REQUIRE_CONFIRMATION · DRY_RUN_ONLY`
  — with reasons, an append-only tamper-evident audit ledger, and a rollback plan.
  Decision surface: `continuity run shell -- …`.
- **Twin** — behavioral model built from your own memory; predicts your stance and
  flags actions that conflict with your canon/rules (evidence-grounded heuristics).
- **Control plane** — correct / redact / rollback / export frontiers and memories;
  you own the data.
- **MCP server** — stdio server exposing **12 tools** (`remember`, `recall`,
  `context`, `forget`, `list_namespaces`, …) for MCP-capable clients
  (Claude Desktop / Claude Code).
- **CLI** — `cos` (memory/continuity) and `continuity` (gate) entry points.
- **HTTP API** — optional tiny server (`cos api --port 8077`) with `/recall`,
  `/remember`, etc.
- **Docker** — `Dockerfile` + `docker-compose.yml` for containerized deploys.
- **Benchmarks** — reproducible harnesses in `bench/` (`recall_bench.py`,
  `locomo_bench.py`, `continuitybench.py`, `owasp_llm_bench.py`).

### Packaging
- Apache-2.0 license, Python 3.10+, **stdlib-only core** (zero required deps).
- Optional extras: `[fast]` (FastEmbed/ONNX, recommended real embedder),
  `[st]` (sentence-transformers), `[dev]` (pytest).

### Internal
- Honest open audits shipped in-tree: `AUDIT_DEVIL_2026-06-17.md`,
  `AUDIT_GATEWAY_DEVIL_2026-06-17.md`, with tracked follow-ups.
- Build artifacts removed from version control (`9f91efa`).

---

[Unreleased]: https://github.com/continuityos/continuityos/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/continuityos/continuityos/releases/tag/v0.7.0
