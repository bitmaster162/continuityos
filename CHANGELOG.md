# Changelog

All notable changes to **ContinuityOS** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

ContinuityOS is a local-first, MCP-native **durable memory + continuity + governance**
layer for AI agents and humans. Core is stdlib-only, stores everything in one SQLite
file, and runs with zero external services. Apache-2.0.

## [0.9.0] — 2026-07-05

Focus: making ContinuityOS a portable, composable engine ready for open-source launch —
migrate history in, export rules out, meter usage, and let cognitive layers build on top.

### Added
- **`cos import`** — migrate your AI history into memory from **six vendors**: ChatGPT (DAG
  backward-traversal, drops regenerated branches), Claude (human→user, thinking blocks,
  memories/projects), Gemini (Takeout), Grok (BSON dates), Mistral, Perplexity (dual-schema).
  Cross-vendor dedup via the **PAM `content_hash`** standard. Bi-temporal: each memory's
  `valid_from` is the original message time, so `recall --as-of` reconstructs what you knew then.
  Offline, no API keys; `--extract` distills typed facts, `--dry-run` previews.
- **`cos rules`** — export canon + rules to the config files coding agents auto-load: `CLAUDE.md`,
  `AGENTS.md`, `.cursor/rules/continuityos.mdc`. One source of truth flows into every agent.
- **`cos usage`** — RaaS metering: a durable usage ledger with plan-based quotas
  (free/pro/team/enterprise) enforced fail-closed, plus a Stripe/Unkey billing seam. Foundation
  for a hosted, metered governance API.
- **`cos moneymap`** — build a tiered monetization map from your own data (`--from <dir>` +
  optional `--from-memory`); heuristic price/offer extraction, local only. Added as step 6 of
  the `cos setup` wizard.
- **Key-based `find()` + `upsert()`** (contributed upstream from an independent cognitive-memory
  integration) — `find(namespace, key)` is a deterministic point-read; `upsert(text, namespace,
  key)` is create-or-update by semantic key (append-only: history kept via supersede). New `key`
  column + `(namespace, key)` index. Exposed across the Python API, the CLI (`cos remember -K`,
  `cos find`), and the MCP server (now 19 tools).

- **`cos advocate`** — a built-in **devil's advocate**: challenges any claim/action against your
  own memory (contradictions, superseded facts, missing evidence, canon conflicts, overconfidence,
  dishonest omissions, irreversible actions) → verdict STOP/RECONSIDER/PROCEED. **Auto-gated** at
  `cos checkpoint`/`close`/`boot` so consequential moves are challenged before they land. Rubric in `ADVOCATE.md`.
- **`cos audit`** — full-system audit: memory inventory + invariants (append-only integrity,
  bi-temporal ordering, canon presence, dangling supersede pointers). `--devil` runs the advocate
  over every failing finding — an EU-AI-Act Article-12-style queryable decision record.
- **`cos bus`** (alias `cos a2a`) — a zero-dep agent-to-agent message bus (JSON-RPC over stdlib
  `http.server`) with **HMAC capability tokens** scoped read/write. (Renamed from `a2a` to avoid
  confusion with the Linux-Foundation A2A protocol.)
- **`cos epoch`** — a git-like DAG of epoch results: `commit`/`branch`/`log`/`graph`. Each epoch's
  metrics become an append-only commit; branches fork like git. Feeds a Three.js graph viewer.
- **HTTP API** — `cos api` gains `/epoch/graph`, `/epoch/commit`, and generic `/graph/<name>`
  (serve any named graph live from SQLite) + CORS.
- **`cos scan`** (long-session SRD mitigation), **`cos update`** (self-update from PyPI/git,
  offline-safe, consent-gated), **MECW** (maximum effective context window + compaction threshold),
  and **pass-by-reference pointers + OCC** (`write_checked`, conflict-detecting writes).
- **Reproducible benchmark** — `bench/recall_bench.py`: honest, zero-external-call recall +
  knowledge-update/temporal correctness + latency (we publish weaknesses too; no gamed leaderboard number).

### Changed
- **`cos doctor` output is ASCII** (no emoji) so it never crashes cp1252 Windows consoles.
- README gains a **"Composable — built on in the wild"** section (Sim-OS/Pandora bridge + the
  cognitive-layer integration that fed `find`/`upsert` back upstream).

### Fixed
- **Packaging** — `[tool.setuptools.packages.find]` restored + `exclude` for `demo/bench/docs`
  so `pip install -e .` succeeds; project version corrected to `0.9.0` (was mislabeled `0.8.8`).

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
