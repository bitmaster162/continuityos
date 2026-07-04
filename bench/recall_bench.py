#!/usr/bin/env python3
"""ContinuityOS memory micro-benchmark — HONEST, runnable, zero external calls.

Not a LoCoMo/LongMemEval leaderboard entry (those need real embeddings + an LLM
judge). This measures what CoS is actually built to do well, on the DEFAULT
zero-dep HashingEmbedder, so anyone can reproduce with `python bench/recall_bench.py`:

  1. Recall@k   — keyword vs paraphrase queries (default embedder is weak on
                  paraphrase by design; `pip install continuityos[fast]` fixes it).
  2. Knowledge-update / temporal correctness — after a fact is superseded, does
     `current_only` return the NEW value and `as_of=<old>` return the OLD one?
     (LoCoMo has NO knowledge-update questions; this is CoS's core wedge.)
  3. Latency p50/p95 and external token cost (0 — fully local).

All numbers below are measured on this machine at run time. No hardcoded scores.
"""
from __future__ import annotations
import os, sys, time, json, statistics, tempfile

os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from continuityos.memory import Memory

NS = "bench"

# ---- gold recall set: (fact, keyword-query, paraphrase-query) --------------
GOLD = [
    ("Robert prefers the Apache-2.0 license for all open-source projects.",
     "Apache-2.0 license preference", "which software license does he like to use"),
    ("The Sovereign Arena runs 150 paper-trading bots on a single VPS.",
     "Sovereign Arena 150 paper bots", "how many simulated traders are in the arena"),
    ("ContinuityOS stores memory in a local-first SQLite database.",
     "ContinuityOS SQLite storage", "where does the system keep its data on disk"),
    ("The governance gate rejects any bot that fails the expectancy check.",
     "governance gate expectancy rejection", "what blocks an underperforming strategy from promotion"),
    ("VECM cointegration analysis found a lag from liquidations to order-book depth.",
     "VECM cointegration liquidation lag", "what did the error-correction model reveal about liquidations"),
    ("The digital twin summarizes a user's durable preferences and goals.",
     "digital twin preferences goals", "what component profiles the long-term user"),
    ("Bi-temporal facts track valid_from and valid_to separately from created_at.",
     "bi-temporal valid_from valid_to", "how are true-in-world times separated from learned times"),
    ("The MCP server exposes seventeen memory and governance tools.",
     "MCP server seventeen tools", "how many tools does the model-context-protocol endpoint offer"),
    ("Hermes workers were spamming Telegram due to a misconfigured cron.",
     "Hermes Telegram cron spam", "why did the background workers flood the chat"),
    ("The BitEvo orchestrator coordinates the whole trading ecosystem.",
     "BitEvo orchestrator trading", "which service ties the trading stack together"),
    ("Checkpoints let a session resume without losing canon or frontiers.",
     "checkpoints resume canon frontiers", "what lets work continue across restarts"),
    ("The extractor keeps only typed durable facts, not every raw turn.",
     "extractor typed durable facts", "what filters conversation into lasting knowledge"),
    ("Grok exports leak BSON date wrappers into user JSON archives.",
     "Grok BSON date export", "what timestamp quirk appears in xAI downloads"),
    ("Gemini Takeout truncates long model responses to save disk space.",
     "Gemini Takeout truncation responses", "which vendor drops long answers from its archive"),
    ("The PAM content_hash normalizes text with Unicode NFC before hashing.",
     "PAM content_hash Unicode NFC", "how does portable memory dedup across platforms"),
    ("Optimistic concurrency control raises a Conflict on a stale write.",
     "optimistic concurrency Conflict stale write", "what prevents two agents overwriting each other"),
    ("The Antigravity worker handles long-running background research jobs.",
     "Antigravity worker background research", "which agent runs the slow research tasks"),
    ("Robert wants all deliverables saved to the workspace folder, not scratch.",
     "save deliverables workspace folder", "where should finished files be written"),
    ("The SCAN protocol tracks Security-Recall Divergence across turns.",
     "SCAN protocol Security-Recall Divergence", "what measures safety drift over a long chat"),
    ("Maximum Effective Context Window for opus is about 185000 tokens.",
     "Maximum Effective Context Window opus 185000", "what is the practical context limit for the big model"),
    ("The arena database is backed up nightly with pg_dump to cloud storage.",
     "arena pg_dump nightly backup", "how is the trading database protected from loss"),
    ("Answer capsules are 40 to 110 words placed under an H2 question.",
     "answer capsule 40 110 words H2", "what is the short GEO summary block format"),
    ("The updater checks PyPI daily and caches the result offline-safe.",
     "updater PyPI daily cache offline", "how does the client know a new version exists"),
    ("Claude exports label the user role as human, not user.",
     "Claude export human role label", "what does Anthropic call the user in its download"),
    ("The symbolic firewall blocks untrusted instructions from tool output.",
     "symbolic firewall untrusted instructions", "what stops injected commands from tool results"),
    ("Robert's canon is to ship honest numbers, never inflate results.",
     "canon ship honest numbers", "what is the rule about reporting metrics"),
    ("Knowledge Objects carry a stable key so they can be upserted.",
     "Knowledge Objects stable key upsert", "what lets a fact be updated in place by name"),
    ("The wizard setup now has eight steps including a monetization map.",
     "wizard eight steps monetization map", "how many stages does onboarding have now"),
    ("Perplexity threads keep citation markers merged with a sources list.",
     "Perplexity citation markers sources", "how are references preserved in that export"),
    ("Replication reproduced twelve of fifteen live strategy signals.",
     "replication twelve of fifteen signals", "how many strategies were successfully reproduced"),
]

# ---- knowledge-update chains: (original, updated, keyword-query) ------------
UPDATES = [
    ("The project version is 0.8.8.", "The project version is 0.9.0.", "current project version"),
    ("The arena runs 100 bots.", "The arena runs 150 bots.", "how many bots in the arena"),
    ("Deploy target is Heroku.", "Deploy target is Vercel.", "where do we deploy the site"),
    ("The gate pass rate is 3 of 29.", "The gate pass rate is 0 of 29.", "gate pass rate backtests"),
    ("Preferred embedder is SentenceTransformer.", "Preferred embedder is FastEmbed.", "preferred embedder"),
    ("The MCP server has 12 tools.", "The MCP server has 17 tools.", "number of MCP tools"),
    ("Backups go to local disk.", "Backups go to cloud storage.", "where do backups go"),
    ("License is MIT.", "License is Apache-2.0.", "current license"),
    ("Context window budget is 128000 tokens.", "Context window budget is 185000 tokens.", "context window budget"),
    ("The wizard has 6 steps.", "The wizard has 8 steps.", "how many wizard steps"),
    ("Forward-paper had 1500 observations.", "Forward-paper had 2331 observations.", "forward paper observations"),
    ("The guide count on the site is 95.", "The guide count on the site is 143.", "how many guides on the site"),
    ("Pricing Pro tier is 199 per month.", "Pricing Pro tier is 249 per month.", "pro tier price"),
    ("Replication reproduced 8 signals.", "Replication reproduced 12 signals.", "replicated signal count"),
    ("The updater checks weekly.", "The updater checks daily.", "how often updater checks"),
    ("Robert prefers verbose explanations.", "Robert prefers concise direct answers.", "preferred answer style"),
    ("Expectancy median is -0.30R.", "Expectancy median is -0.258R.", "median expectancy"),
    ("The stack runs on Windows.", "The stack runs on a Linux VPS.", "what OS runs the stack"),
    ("Twin refresh is manual.", "Twin refresh is automatic on checkpoint.", "how does the twin refresh"),
    ("Namespace default is notes.", "Namespace default is imported for imports.", "default import namespace"),
]

# ---- distractors: fill the store so retrieval isn't trivial ----------------
DISTRACTORS = ["Note number %d: an unrelated background fact about topic %d in domain %d."
               % (i, i % 37, i % 7) for i in range(100)]


def build(mem: Memory):
    t0 = time.time() - 90 * 86400
    gold_ids = {}
    for i, (fact, _kw, _pa) in enumerate(GOLD):
        gold_ids[i] = mem.remember(fact, namespace=NS, valid_from=t0 + i * 3600, mtype="fact")
    for d in DISTRACTORS:
        mem.remember(d, namespace=NS, valid_from=t0)
    chains = []
    for i, (orig, upd, _q) in enumerate(UPDATES):
        t_old = t0 + i * 3600
        t_new = t0 + 60 * 86400 + i * 3600
        oid = mem.remember(orig, namespace=NS, valid_from=t_old, mtype="fact")
        nid = mem.supersede(oid, upd, valid_from=t_new, mtype="fact")
        chains.append((oid, nid, t_old, t_new))
    return gold_ids, chains


def hit_at_k(mem, query, target_id, k):
    res = mem.recall(query, k=k, namespace=NS)
    ids = []
    for r in res:
        rid = getattr(r, "id", None)
        if rid is None and hasattr(r, "meta"):
            rid = None
        ids.append(rid)
    # fall back to text match if id not exposed
    if any(i is None for i in ids):
        target_text = mem.store.get(target_id)["text"]
        return any(getattr(r, "text", "") == target_text for r in res)
    return target_id in ids


def main():
    db = os.path.join(tempfile.mkdtemp(), "bench.db")
    mem = Memory(db)
    build_t = time.time()
    gold_ids, chains = build(mem)
    build_ms = (time.time() - build_t) * 1000
    total_mem = len(GOLD) + len(DISTRACTORS) + 2 * len(UPDATES)

    # --- recall@k, keyword vs paraphrase ---
    lat = []
    kw_hits = {1: 0, 3: 0, 5: 0}
    pa_hits = {1: 0, 3: 0, 5: 0}
    for i, (fact, kw, pa) in enumerate(GOLD):
        tid = gold_ids[i]
        for k in (1, 3, 5):
            if hit_at_k(mem, kw, tid, k):
                kw_hits[k] += 1
            if hit_at_k(mem, pa, tid, k):
                pa_hits[k] += 1
        t = time.time(); mem.recall(kw, k=5, namespace=NS); lat.append((time.time() - t) * 1000)

    # --- knowledge-update / temporal correctness ---
    temporal_ok = 0
    current_ok = 0
    for (oid, nid, t_old, t_new), (orig, upd, q) in zip(chains, UPDATES):
        # current_only should surface the NEW value
        cur = mem.recall(q, k=5, namespace=NS, current_only=True)
        cur_texts = [getattr(r, "text", "") for r in cur]
        if upd in cur_texts and orig not in cur_texts:
            current_ok += 1
        # as_of the old time should surface the OLD value and NOT the new one
        old = mem.recall(q, k=10, namespace=NS, as_of=t_old + 1)
        old_texts = [getattr(r, "text", "") for r in old]
        if orig in old_texts and upd not in old_texts:
            temporal_ok += 1

    n = len(GOLD); u = len(UPDATES)
    report = {
        "total_memories": total_mem,
        "build_ms": round(build_ms, 1),
        "recall_keyword": {f"@{k}": round(100 * kw_hits[k] / n, 1) for k in (1, 3, 5)},
        "recall_paraphrase": {f"@{k}": round(100 * pa_hits[k] / n, 1) for k in (1, 3, 5)},
        "knowledge_update_current_pct": round(100 * current_ok / u, 1),
        "temporal_as_of_pct": round(100 * temporal_ok / u, 1),
        "recall_latency_ms": {"p50": round(statistics.median(lat), 3),
                               "p95": round(sorted(lat)[int(0.95 * len(lat)) - 1], 3),
                               "mean": round(statistics.mean(lat), 3)},
        "external_tokens_per_query": 0,
        "external_api_calls": 0,
        "embedder": "HashingEmbedder (zero-dep default)",
    }
    print("=" * 66)
    print("ContinuityOS memory micro-benchmark  (default zero-dep embedder)")
    print("=" * 66)
    print(f"corpus: {total_mem} memories  |  build: {report['build_ms']} ms  |  db: SQLite (local)")
    print(f"recall@1/3/5  keyword    : {report['recall_keyword']['@1']:5}% / {report['recall_keyword']['@3']:5}% / {report['recall_keyword']['@5']:5}%")
    print(f"recall@1/3/5  paraphrase : {report['recall_paraphrase']['@1']:5}% / {report['recall_paraphrase']['@3']:5}% / {report['recall_paraphrase']['@5']:5}%  (weak by design; [fast] embedder lifts this)")
    print(f"knowledge-update (current_only picks NEW value) : {report['knowledge_update_current_pct']}%")
    print(f"temporal as-of  (as_of=<old> picks OLD value)   : {report['temporal_as_of_pct']}%")
    print(f"recall latency  p50/p95/mean : {report['recall_latency_ms']['p50']} / {report['recall_latency_ms']['p95']} / {report['recall_latency_ms']['mean']} ms")
    print(f"external tokens/query : {report['external_tokens_per_query']}   external API calls : {report['external_api_calls']}")
    print("=" * 66)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_results.json")
    json.dump(report, open(out, "w"), indent=2)
    print("wrote", out)
    return report


if __name__ == "__main__":
    main()
