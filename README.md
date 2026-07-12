# ContinuityOS

[![tests](https://github.com/bitmaster162/continuityos/actions/workflows/ci.yml/badge.svg)](https://github.com/bitmaster162/continuityos/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/continuityos.svg)](https://pypi.org/project/continuityos/) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-Apache--2.0-green)

[![PyPI](https://img.shields.io/pypi/v/continuityos)](https://pypi.org/project/continuityos/) [![Python](https://img.shields.io/pypi/pyversions/continuityos)](https://pypi.org/project/continuityos/) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)


> ## ContinuityOS — continuity engine + controlled governance runner
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

**Durable memory + continuity layer for AI agents and humans.** Local-first, with no required
external service for the core memory path. Apache-2.0.

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
- **For agents *and* humans.** Use it from your code, from the CLI, from an MCP-capable client (Claude Desktop / Claude Code), or over a tiny HTTP API.
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

### From the CLI

```bash
cos remember "Robert prefers Apache-2.0 licenses" -n rules -t license
cos remember "ContinuityOS = hybrid memory: FTS + vectors" -n projects
cos recall  "which license should I pick?"
# 0.54 [rules] Robert prefers Apache-2.0 licenses  (semantic 0.22 + keyword)
cos namespaces
```

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

### As an MCP server (Claude Desktop / Claude Code)

ContinuityOS ships an MCP stdio server so an agent can `remember` and `recall` on its own. Add to your MCP client config:

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
Now the agent pulls relevant memory automatically before answering — and writes new facts back as it learns it.

**Recommended:** use the cross-platform bridge instead of `cos serve`:

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

Over MCP the agent gets `checkpoint`, `handoff`, `doctor`, `set_frontier` tools too — so it maintains its own continuity, not just its recall.

---

## Governance — devil's advocate, audit, gate

ContinuityOS isn't just recall — it's the **governance & audit layer** for agent memory, built for
the EU-AI-Act era (Article-12 queryable decision records), not the LoCoMo leaderboard.

- **`cos advocate "<claim>"`** — a running **devil's advocate** that challenges a claim or action
  against your own memory (contradictions, stale facts, missing evidence, canon conflicts,
  overconfidence, dishonest omissions, irreversible actions) → verdict STOP / RECONSIDER / PROCEED.
  Auto-gated at `checkpoint`/`close`/`boot`. Rubric in `ADVOCATE.md`.
- **`cos audit [--devil]`** — memory inventory + invariants (append-only integrity, bi-temporal
  ordering, canon, dangling pointers); emits an Article-12-style record.
- **Governance preflight** — for actions explicitly routed through the runner or an installed hook, a decision
  (ALLOW / WARN / HOLD / DENY / REQUIRE_CONFIRMATION / DRY_RUN_ONLY) with reasons, rollback plan, and
  an append-only ledger.

```bash
cos advocate "All 150 bots are profitable and guaranteed to win"   # flags overconfidence + honesty
cos audit --devil                                                   # invariants + adversarial pass
```

---

## How it works

```
            remember(text, namespace, tags)
                        │
                        ▼
        ┌───────────────────────────────┐
        │            Store               │   one local SQLite file
        │  items  +  FTS5  +  vectors    │
        └───────────────────────────────┘
                        ▲
          recall(query) │  HYBRID rank
            ┌───────────┴───────────┐
   structural / keyword       semantic / vector
   (FTS5 + namespace)         (cosine over embeddings)
            └───────────┬───────────┘
                  blended score → top-k
```

- **Structural layer** — `namespace` (folder-like) + `tags` + FTS5 full-text index.
- **Semantic layer** — each memory is embedded to an L2-normalized vector; recall ranks by cosine similarity.
- **Hybrid score** — `semantic_weight · semantic + (1 − semantic_weight) · keyword` (tunable; default 0.6).
- **Embeddings are pluggable** — the default `HashingEmbedder` is deterministic and fully offline (great for privacy and tests). For best semantic quality, pass any `str → list[float]` callable (e.g. a `sentence-transformers` model):

  ```python
  from sentence_transformers import SentenceTransformer
  enc = SentenceTransformer("all-MiniLM-L6-v2")
  m = Memory("memory.db", embedder=lambda t: enc.encode(t, normalize_embeddings=True).tolist())
  ```

---

## Privacy

ContinuityOS core does not upload memory content. Memory is a local SQLite file; governance and
metering can create additional local databases. `.gitignore` excludes common SQLite artifacts and
downloaded benchmark data, but operators remain responsible for excluding their own import/export
directories and secrets.

---

## Governance boundary status

ContinuityOS currently provides a deterministic decision engine, an argv-only controlled CLI
runner, and opt-in host hooks. These are useful enforcement points **inside the paths that are
actually wired to them**. The MCP `preflight_action` tool is advisory: exposing it does not force
an agent's other tools through it. Raw shell access, a direct SDK call, or an unconfigured host can
bypass the gate entirely.

The ledger is append-only and hash-chained, with transactional concurrent appends, but it is not
cryptographically signed or externally anchored. Local rollback is materialized by the controlled
CLI immediately before approved execution for supported explicit file targets; advisory preflight
responses do not claim that a snapshot already exists. These artifacts can support an audit, but
they are not by themselves evidence of regulatory compliance. See [THREAT_MODEL.md](THREAT_MODEL.md)
and [BUILD_GATE_STATUS.md](BUILD_GATE_STATUS.md).

## Two-tier memory & cost-aware routing

The strongest 2026 agents don't win on a bigger context window — they win on *how they handle the finiteness of context*. ContinuityOS implements the two-tier pattern Anthropic and OpenAI both converge on:

- **Session memory** — the auto-compactible state of the current run (goal, live hypotheses, found IDs, tool outcomes, unresolved blockers). Carried forward instead of re-derived each turn.
- **Long-term memory** — durable lessons, stable user preferences, recurring patterns, anti-patterns, domain facts. **One lesson per file; update the existing note, don't spawn duplicates** — the same discipline this repo's memory files follow.

`context(query, k, max_tokens=…, compact=…)` packs the most relevant long-term memories until a token budget is hit, so recall stays cheap, and its output order is deterministic — which matters for **prompt-cache stability**.

**Cache-friendly memory rules** (preserve the prompt-cache hash; cache miss = paying full price every turn):

1. Never put volatile values (`datetime.now()`, random IDs, per-turn counters) in the system prompt or any cached prefix — they reset the cache every call. Put them in the body of the last user message.
2. Keep tool definitions and the memory block in a **stable, sorted order** so the cached prefix is byte-identical across turns (`compact=True` + deterministic packing does this).
3. Cache thresholds and provider behavior change; verify the current provider documentation before
   relying on a minimum prefix size.
4. To change instructions mid-run without busting the cache, inject a `role:"system"` message *into the history* rather than editing the cached system prompt.

**Cost-aware routing.** `estimate_cost(text, model_id, output_tokens)` can compare a context block
against the package's static `MODEL_REGISTRY`. Those entries are estimates, not a live price feed;
verify provider pricing before a financial or routing decision.

## Why continuity, not just memory

ContinuityOS stores continuity state outside a model: canon, rules, bi-temporal facts, and decision
checkpoints can be reloaded after a model or vendor change. `cos boot` reconstructs a context pack;
it does **not** prove that the new model is the same agent or will reproduce prior behavior.

## Sim-OS — closed-loop simulation on top of the memory core

Beyond memory, ContinuityOS ships an experimental layer: [`continuityos/sim/`](continuityos/sim/)
is a durable OODA-style loop with a mock simulation engine, risk scoring, loop detection, and local
rollback hooks. It is designed to keep unverified results out of canon, but is not a sandbox or a
guarantee against canon contamination.

```bash
cos sim --objective edge --iters 6      # run the closed loop (mock engine)
```

See [continuityos/sim/README.md](continuityos/sim/README.md) for the architecture.

## Extension seams

ContinuityOS is a memory + governance library, not a closed product. The [`Memory`](continuityos/memory.py)
API, advisory governance preflight, and [`sim/`](continuityos/sim/) package are available extension
seams. The in-repository Sim-OS/Pandora code is an experimental integration; no independent-user,
retention, or production-dependency claim is made here without a linked receipt.

## Honest limits (threat model)

We'd rather tell you the edges than oversell. Full detail in [THREAT_MODEL.md](THREAT_MODEL.md).

- **Installation is not interception.** Only the controlled runner and correctly installed hooks enforce a result. The MCP preflight tool is advisory, and direct/raw tools remain outside this boundary.
- **The classifier is not an oracle.** It covers known shell/file/git patterns and validates typed paths where supplied. It does **not** understand arbitrary application logic or close the symlink/path TOCTOU gap between decision and execution.
- **Rollback is narrow and local-only.** The v1 executor snapshots explicit regular-file, SQLite, and not-yet-existing file targets. Directories, symlinks, remote APIs, GitHub operations, messages, and transactions are not reversible through this module.
- **The ledger is tamper-evident, not tamper-proof.** Concurrent appends are serialized, but there is no signature, separate writer identity, or external anchor.
- **Default embedder is weak on purpose.** The zero-dependency `HashingEmbedder` is fast but semantically shallow. For real synonym/paraphrase recall install `continuityos[fast]` (ONNX, ~bge-small) or `[m2v]` (30MB static). We publish honest LoCoMo *retrieval* numbers in `BENCHMARKS.md` — not answer-graded marketing figures.
- **Memory can go stale.** A fact true last week can be wrong today. Use bi-temporal `supersede()` / `recall(current_only=True)` so corrections hide stale facts instead of contradicting them. Don't hand an agent raw memory without the current-only filter for state-sensitive decisions.
- **It asks for discipline.** Continuity relies on session-close rituals (`cos checkpoint`) and periodic `cos doctor`. Skip them and the store drifts toward a log dump. This is a feature (auditable thread), but it is real operator work.
- **Prompt-cache hygiene.** If you inject memory into a system prompt, keep it deterministic — a dynamic value (e.g. `datetime.now()`) busts the cache and you pay full context cost every call. `context(..., compact=True)` returns cache-stable output; don't wrap it in per-call timestamps.

Best fit today: **operators and teams that need auditable, governed continuity** (regulated internal ops, on-call/shift handoff, coding agents with rollback). Overkill if you just want Git-style backups and paste context by hand.

## Status

Package version: **v0.9.0**. Current test and governance-corpus results are recorded in
[BUILD_GATE_STATUS.md](BUILD_GATE_STATUS.md); the CI workflow is the authoritative moving signal.
