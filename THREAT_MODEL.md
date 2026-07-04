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
append-only, tamper-evident ledger.

**Does not:**
- Understand arbitrary application logic. A subtle bug *inside* a script it is allowed to
  run is out of scope. Gate the script's category, not its internals.
- Sandbox execution. It decides yes/no; it does not contain a process that runs.
- Catch novel obfuscation guaranteed. It is a deterministic classifier, not an oracle.
  `exec` mode is argv-only and refuses shell operators; `shell` mode runs them but is
  classified more strictly. Prefer `exec`.

## Rollback scope

Rollback reverts **local file/DB state only**. It **cannot** undo irreversible external
side effects: a bad API call to prod, a deleted remote repo, a sent transaction, a placed
order. Those must be gated *before* execution — never rely on rollback to clean them up.
Reversibility is a property you design upstream, not a button you press after.

## Memory correctness

- **Staleness.** A fact true last week can be wrong today. Use bi-temporal `supersede()`
  and `recall(current_only=True)` so corrections hide stale facts. Do not feed raw memory
  to a state-sensitive decision without the current-only filter.
- **Provenance.** Facts carry source/timestamp/confidence. Low-confidence or
  unknown-source memory should not drive irreversible actions.
- **Poisoning.** If an attacker can write to your memory store, they can influence recall.
  Treat write access to the DB as a privileged boundary; the gate reads canon, so canon
  integrity matters.

## Privacy

Local-first by construction: one SQLite file, no cloud, no account, no telemetry. Secrets
(API keys) belong in `~/.continuityos/.env` (chmod 600), never in canon text or git. The
optional embedders run locally; nothing is sent to a third party by the core.

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

## Reporting

Found a real bypass or a memory-poisoning path? Open a GitHub issue or contact the
maintainers. Honest edge reports are more welcome than benchmark wins.
