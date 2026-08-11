# ContinuityOS

[![tests](https://github.com/bitmaster162/continuityos/actions/workflows/ci.yml/badge.svg)](https://github.com/bitmaster162/continuityos/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/continuityos.svg)](https://pypi.org/project/continuityos/) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-Apache--2.0-green)

**Durable local memory + continuity for AI agents and humans.** Import your existing AI history, preserve canon/checkpoints/open work, connect an MCP client, and resume in a fresh session without rebuilding context by hand.

ContinuityOS v0.10 puts the product workflow first:

```text
install -> setup/import -> connect -> status -> fresh-session continuity proof -> resume
```

```bash
pip install continuityos
cos setup
cos import ~/Downloads/chatgpt-export/conversations.json --extract
cos connect claude --dry-run
cos connect claude --yes
cos status
cos demo continuity
cos boot
```

`cos connect` supports Claude and Cursor as managed configurations and emits guidance for Hermes and generic MCP clients. `cos status` is read-only. `cos demo continuity` uses an isolated temporary database and a separate Python process; it does not read or write your normal memory database.

> ## Controlled governance runner
>
> Calls explicitly routed through `continuity run` or a correctly installed host hook receive a
> decision — `ALLOW · WARN · HOLD · DENY · REQUIRE_CONFIRMATION · DRY_RUN_ONLY` — with reasons,
> a tamper-evident local ledger, and a local rollback plan where the controlled runner can
> materialize one. ContinuityOS does **not** intercept raw shell/MCP/tool calls by merely being
> installed; mandatory broker enforcement remains future work. Apache-2.0.
>
> ```bash
> continuity run shell -- rm -rf /     # ⛔ BLOCKED — command was NOT executed
> continuity run shell -- npm test     # ✓ ALLOW — runs
> ```
>
> ContinuityBench v0 is a **30-case, hand-labeled regression corpus**, not a security-boundary
> certification. The current verified run is summarized in [BUILD_GATE_STATUS.md](BUILD_GATE_STATUS.md),
> and CI fails if the corpus regresses. The bundled MCP adapter supplies its local continuity
> context; third-party adapters must explicitly provide and validate their own context.
>
> The memory + continuity layers below are the **context engine** that powers those decisions.

---

![ContinuityOS demo: bi-temporal recall and governance gate](docs/demo.gif)

The tested core combines **memory** (hybrid recall) with **continuity** (canon, frontiers, loops,
checkpoints, doctor, handoff). The repository also contains experimental primitives: an
authority-tagged multi-agent wrapper, a retrieval/keyword-based `Twin`, simulation helpers, and an
operator control plane. These experiments are not evidence of a validated behavioral twin,
co-evolution outcome, or production multi-agent product.

Your Claude / ChatGPT / agent forgets everything between sessions. ContinuityOS is a small local memory layer that stores what matters — who you are, your projects, your rules, decisions you've made — and gives it back when it's relevant. It recalls **both structurally** (folder-like namespaces + keyword search) **and semantically** (vector similarity), so the right memory surfaces whether you match the words or just the meaning.

The core does not upload user memory content: the memory store is one local SQLite file, while
governance and metering can create additional local databases. Update checks and optional model
downloads can make outbound requests; there is no account requirement or product telemetry.

---

## Why

- **Agents forget.** Every new session starts cold. ContinuityOS persists context across sessions and tools.
- **Hybrid recall.** Keyword-only memory misses paraphrases; pure-vector memory misses exact facts and structure. ContinuityOS blends both.
- **Structure like folders.** Memories live in namespaces — `identity`, `projects`, `rules`, `facts`, `events`, `notes` (or your own) — so recall can be scoped and a human can browse it.
- **For agents *and* humans.** Use it from your code, from the CLI, from an MCP-capable client (Claude Desktop / Claude Code / Cursor / Hermes), or over a tiny HTTP API.
- **Local-first & private.** Core is **stdlib-only** — no required dependencies, no services. Drop-in to anything.

---

## Install

```bash
pip install continuityos          # core (stdlib-only)
# optional, for production-grade embeddings:
pip install "continuityos[fast]"        # recommended: FastEmbed / ONNX
pip install "continuityos[st]"          # sentence-transformers
pip install "continuityos[m2v]"         # light static model2vec
pip install "continuityos[embeddings]"  # all optional embedders
```

Requires Python 3.10+.

---

## Quick start

### Product workflow

```bash
cos --version
cos setup
cos import ~/Downloads/chatgpt-export/conversations.json --extract
cos connect --status
cos connect claude --dry-run
cos connect claude --yes
cos status
cos demo continuity
cos boot
```

Use `cos --help` for the product-first command map. For Cursor, replace `claude` with `cursor`. Hermes and `generic-mcp` return exact manual connection guidance instead of silently editing an unsupported config format.

### Memory CLI

```bash
cos remember "Robert prefers Apache-2.0 licenses" -n rules -t license
cos remember "ContinuityOS = hybrid memory: FTS + vectors" -n projects
cos recall  "which license should I pick?"
# 0.54 [rules] Robert prefers Apache-2.0 licenses  (semantic 0.22 + keyword)
cos namespaces
```

### Common Operational Memory v1 (shadow-only)

ContinuityOS includes a separate evidence-bound operational ledger. It does not replace
Control Center current truth and cannot apply state changes:

```bash
continuity-memory init
continuity-memory import-broker MASTER_RETURN_REGISTRY_R64.jsonl
continuity-memory snapshot --out operational_snapshot.json
continuity-memory checkpoint --label after-import
continuity-memory verify
```

It stores schema-enforced append-only events, bi-temporal claims, authority-bound decisions,
physical broker custody and replay checkpoints in a **local SQLite WAL database outside DriveFS**. Imported
returns are forced to `content_status=UNREVIEWED` and `apply_status=NOT_APPLIED`. See
[`docs/COMMON_OPERATIONAL_MEMORY_V1.md`](docs/COMMON_OPERATIONAL_MEMORY_V1.md).

For evidence-bound project memory, the operator workflow is split deliberately between verified
current-session READ_ONLY surfaces and separate effectful gates:

```text
Existing project DB:
  continuity-work
    -> continuity-memory-delta             # NOT_APPLIED proposal
    -> continuity-memory-apply             # separate exact authorization; current session unbound

Fresh project DB:
  continuity-memory-bootstrap-plan         # NOT_APPLIED manifest proposal
    -> continuity-memory-bootstrap-check   # point-in-time READ_ONLY validation
    -> continuity-memory-bootstrap         # separate exact authorization; current session unbound
```

`continuity-work`, `continuity-memory-delta`, `continuity-memory-bootstrap-plan`, and
`continuity-memory-bootstrap-check` require a verified current session and never grant execution.
`READY` and proposal terminals are not write permission. `continuity-memory-apply` and
`continuity-memory-bootstrap` are separate effectful gates; they revalidate their exact inputs and
remain shadow-only. None of these commands applies accepted Control Center truth, mutates canonical
state, deploys, dispatches an agent, trades, accesses a wallet, or grants capital permission.

### Import your AI history (6 vendors)

Bring your existing history into ContinuityOS from **ChatGPT, Claude, Gemini, Grok, Mistral,
and Perplexity** — **bi-temporally**, so `cos recall --as-of <date>` reconstructs what you knew
then instead of a flat dump:

```bash
cos import ~/Downloads/chatgpt-export/conversations.json   # ChatGPT (DAG backward-traversal)
cos import ~/Downloads/claude-export/                      # Claude (+ memories.json / projects.json)
cos import ~/Downloads/Takeout/                            # Google Gemini (MyActivity.json)
cos import grok-export.json                                # xAI Grok (BSON dates)
cos import perplexity_thread.json                          # Perplexity (dual-schema)
cos import export.json --extract                           # distill typed facts, not raw turns
```

Auto-detects all six formats; cross-vendor dedup via the **PAM `content_hash`** standard (the same
question asked to different models collapses to one memory). Deterministic and offline (no API keys);
every imported memory's `valid_from` is the original message time.

### From Python

```python
from continuityos import Memory

m = Memory("memory.db")
m.remember("The grid lab K=0.04 cohort led at +$1405 / 3 days", namespace="facts", tags=["trading"])

for hit in m.recall("best grid setup", k=3):
    print(hit.score, hit.namespace, hit.text)

# inject straight into an agent prompt:
print(m.context("what do I know about grid trading?"))
```

### Connect an MCP client

The recommended v0.10 path is the safe product connector:

```bash
cos connect --status
cos connect claude --dry-run
cos connect claude --yes
# or: cursor / hermes / generic-mcp
```

Managed client writes are previewed first, preserve unrelated config keys, create rollback state, and verify MCP initialization after the write. See [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md).

Manual MCP configuration remains available as an advanced fallback:

```json
{
  "mcpServers": {
    "continuityos": {
      "command": "cos",
      "args": ["--db", "~/.continuityos/memory.db", "serve"]
    }
  }
}
```

Tools are reported by the MCP `tools/list` response; use that response as the version-correct inventory.

**Cross-platform bridge fallback:**

```json
{
  "mcpServers": {
    "continuityos": {
      "command": "python",
      "args": ["/path/to/mcp_bridge.py"]
    }
  }
}
```

See [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) for Hermes, Claude Desktop, and Cursor setup.

### Over HTTP (optional)

```bash
cos api --port 8077                       # local-only: 127.0.0.1
curl -s "localhost:8077/recall?q=license&k=3"
curl -s -XPOST localhost:8077/remember -d '{"text":"hello","namespace":"notes"}'
```

Remote bind is intentionally opt-in:

```bash
export CONTINUITYOS_ALLOW_REMOTE=1        # required for --host 0.0.0.0
export CONTINUITYOS_TOKEN='change-me'     # optional bearer auth for HTTP API
cos api --host 0.0.0.0 --port 8077
curl -H "Authorization: Bearer $CONTINUITYOS_TOKEN" "localhost:8077/health"
```

### Real semantic recall (recommended)

The default embedder is offline & dependency-free. For real semantic quality (synonyms, paraphrases), switch in one line:

```python
from continuityos import Memory
from continuityos.embedders import FastEmbedEmbedder   # pip install "continuityos[fast]"
m = Memory("memory.db", embedder=FastEmbedEmbedder())  # bge-small, ONNX, no torch
```

The optional embedder path is available, but no current comparative result artifact is shipped.
See [BENCHMARKS.md](BENCHMARKS.md) for the reproducible zero-dependency floor and its limitations.

### With Docker

```bash
docker compose up -d        # HTTP API on :8077, memory persisted in ./cos-data
```

---

## More than memory — the continuity layer

A chat is a terminal, not memory. ContinuityOS persists the operating state that keeps work coherent across sessions:

- **Canon** — slow, non-negotiable truths (who you are, rules you don't break).
- **Frontiers** — `1 trunk + 1 cash + 1 lab` focus discipline; classify every idea.
- **Open loops** — what's still unfinished, bounded so it can't sprawl.
- **Checkpoints** — every session ends with `delta + next irreversible action + proof`.
- **Doctor** — an anti-drift check: is a cash frontier set? loops bounded? checkpoint fresh? proof attached?
- **Handoff pack** — one block (canon + frontiers + loops + last checkpoint) to resume in a new session or hand to another agent.

```bash
cos frontier trunk continuityos
cos frontier cash  inner-circle
cos loop "ship v0.2 to GitHub"
cos checkpoint --summary "built continuity layer" --next "update sites" --proof continuity.py
cos doctor       # ✅ healthy 5/5  (or flags drift)
cos handoff      # paste this into the next session
```

```python
from continuityos import Continuity
c = Continuity(db="memory.db")
c.add_canon("Proof beats explanation. Closure beats branching.")
c.set_frontier("cash", "inner-circle")
c.checkpoint(summary="...", next_action="...", proof="path/to/artifact")
print(c.doctor())     # anti-drift report
print(c.handoff())    # resume-context block
```
