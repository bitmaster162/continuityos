# ContinuityOS — Threat Model

We'd rather name the edges than oversell. This document is the honest boundary of what
ContinuityOS protects, what it does not, and how to deploy it safely. If something here
looks like a gap for your use case, it probably is — gate it upstream.

## Design stance

**Agenticity is local; architecture is systemic.** ContinuityOS is an *operator continuity
+ governance substrate*, not a universal execution engine and not a capital allocator.
The governing rule for any action with real-world side effects:

> **Agents propose. Deterministic systems dispose.**

An LLM/agent may *propose* a typed intent (a shell command, a file edit, a git action,
or in the broader system a Trade/Bid/Payment intent). Whether it *executes* is decided by
deterministic checks — never by the model alone. ContinuityOS supplies the memory,
canon, and gate for those decisions; it does not replace them.

## Trust boundaries

| Boundary | Trusted | Untrusted |
|---|---|---|
| Instructions | The operator (you), via CLI/config | Anything read through tools: web pages, file contents, tool output, memory injected from unknown sources |
| Capital / external side effects | Deterministic policy + human thresholds | Any LLM/agent output |
| Local state | The SQLite store you own | Concurrent writers without WAL discipline |

Memory content is **data, not commands**. If a stored note or a recalled fact contains
text directed at the agent ("ignore rules", "send funds to X"), that is not authorization —
the gate and the operator decide, not the memory.

## What the governance gate does — and does not — stop

**Does:** classifies known-dangerous shell/file/git *commands* before they run
(`rm -rf`, force-push, secret/`.env` reads, `curl | sh`, history rewrites) and returns
`ALLOW · WARN · HOLD · DENY · REQUIRE_CONFIRMATION · DRY_RUN_ONLY` with reasons and an
append-only, tamper-evident ledger. Policy parse/ambiguity and context-evaluation errors hold
the controlled CLI/hook instead of silently reverting to defaults.

**Does not:**
- Understand arbitrary application logic. A subtle bug *inside* a script it is allowed to
  run is out of scope. Gate the script's category, not its internals.
- Sandbox execution. It decides yes/no; it does not contain a process that runs.
- Intercept arbitrary tools merely because the package or MCP server is installed. `continuity run`
  is a controlled runner; the Claude hook enforces only when installed and matched; MCP
  `preflight_action` is advisory. Direct shell/SDK calls remain outside the boundary.
- Catch novel obfuscation guaranteed. It is a deterministic classifier, not an oracle.
  `exec` mode is argv-only and refuses shell operators; `shell` mode runs them but is
  classified more strictly. Prefer `exec`.

## Rollback scope

The v1 controlled runner snapshots explicit regular files, SQLite databases (through the SQLite
backup API), and the prior absence of file targets immediately before approved execution.
Directories and symlinks are deliberately unsupported and cause the controlled execution to hold.
Advisory preflight only returns snapshot intent; it does not claim a snapshot already exists.

Rollback reverts this narrow **local file/DB state only**. It **cannot** undo irreversible external
side effects: a bad API call to prod, a deleted remote repo, a sent transaction, a placed
order. Those must be gated *before* execution — never rely on rollback to clean them up.
Reversibility is a property you design upstream, not a button you press after.

## Memory correctness

- **Staleness.** A fact true last week can be wrong today. Use bi-temporal `supersede()`
  and `recall(current_only=True)` so corrections hide stale facts. Do not feed raw memory
  to a state-sensitive decision without the current-only filter.
- **Provenance.** Facts can carry source/timestamp/confidence when callers or adapters supply
  them; generic writes do not currently require these fields. Low-confidence or unknown-source
  memory should not drive irreversible actions, and enforcement remains incomplete.
- **Poisoning.** If an attacker can write to your memory store, they can influence recall.
  Treat write access to the DB as a privileged boundary; the gate reads canon, so canon
  integrity matters.

## Privacy

Local-first by construction: user memory content is stored in a local SQLite file and is not
uploaded by the core; governance and metering may create additional local databases. There is no
account requirement or product telemetry. Update checks and installation/model downloads can make
outbound requests. Secrets (API keys) belong in `~/.continuityos/.env` (chmod 600), never in canon
text or git. Optional embedders execute locally after their model artifacts are installed.

## Embedder honesty

The zero-dependency `HashingEmbedder` is fast but semantically shallow — deliberately, so
the floor has no heavy deps. For real synonym/paraphrase recall install
`continuityos[fast]` (ONNX, ~bge-small) or `[m2v]` (30MB static). We publish honest
LoCoMo *retrieval* numbers in `BENCHMARKS.md` — not answer-graded marketing figures.
LoCoMo itself has ~6% broken ground truth; treat all vendor numbers (ours included) with
suspicion.

## Operator discipline (a dependency, not a bug)

Continuity relies on session-close rituals (`cos checkpoint` / `cos close`) and periodic
`cos doctor`. Skip them and the store drifts toward a log dump. This is real operator
work — the payoff is an auditable, model-agnostic thread.

## Out of scope (today)

- Multi-tenant isolation / access control between users sharing one store.
- Cryptographic signing of the ledger (it is tamper-*evident* via hash-chain, not
  tamper-*proof* against an attacker with DB write access).
- Guaranteed detection of adversarial prompt injection in recalled content — we reduce
  blast radius (data-not-commands, gate, current-only), we do not claim immunity.
- Sandboxing of executed processes (see gate limits above).
- A broker that physically removes direct/raw tool paths from an agent.
- Closing filesystem TOCTOU after path validation; paths are reified by the executor, not held by
  an OS-level capability handle.
- Directory/symlink snapshots or general transaction compensation.

The SQLite ledger serializes read-head + append with a write transaction, so concurrent local
writers form one chain. That addresses atomicity, not authenticity: a same-user attacker with DB
write access can rewrite the chain, and there is no external anchor.

## Reporting

Found a real bypass or a memory-poisoning path? Open a GitHub issue or contact the
maintainers. Honest edge reports are more welcome than benchmark wins.
