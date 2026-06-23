"""Recall benchmark harness for ContinuityOS.

Measures recall@k and MRR of the memory engine on a labeled (query -> gold memory)
set. Ships with a small synthetic set; swap `load_dataset()` for LoCoMo /
LongMemEval to publish comparable numbers. Compares embedders side by side.

Run:  python bench/recall_bench.py
"""
from __future__ import annotations
import os, tempfile, time
from continuityos import Memory
from continuityos.embed import HashingEmbedder

# (memory_text, query_that_should_retrieve_it) — synthetic, paraphrased queries
SYNTHETIC = [
    ("The user prefers Apache-2.0 licenses for open-source projects.", "which software license should we pick?"),
    ("Grid cohort K=0.04 was the leader at +$1405 over three days.", "best performing grid density setting"),
    ("Never execute irreversible actions without explicit confirmation.", "is it safe to auto-delete files?"),
    ("ContinuityOS stores memory locally in one SQLite file.", "where is the data kept?"),
    ("The arena runs 150+ trading bots on live Binance data.", "how many agents are in the fleet?"),
    ("MCP lets an agent fetch relevant memory before answering.", "how does the model recall context automatically?"),
    ("Inner Circle subscription costs $299 per month.", "price of the premium tier"),
    ("Hybrid recall blends keyword FTS with vector cosine.", "how does search combine methods?"),
    ("The digital twin predicts a stance from recorded rules.", "what does the twin layer do?"),
    ("Redact removes private memories for privacy compliance.", "how to delete sensitive data?"),
]

def load_dataset():
    return SYNTHETIC

def evaluate(embedder, data, ks=(1, 3, 5)):
    db = os.path.join(tempfile.mkdtemp(), "bench.db")
    m = Memory(db, embedder=embedder)
    ids = [m.remember(text, namespace="facts") for text, _ in data]
    hits = {k: 0 for k in ks}; rr = 0.0; t0 = time.time()
    for i, (_, query) in enumerate(data):
        ranked = m.recall(query, k=max(ks))
        ranked_ids = [h.id for h in ranked]
        gold = ids[i]
        for k in ks:
            if gold in ranked_ids[:k]:
                hits[k] += 1
        if gold in ranked_ids:
            rr += 1.0 / (ranked_ids.index(gold) + 1)
    n = len(data); dt = (time.time() - t0) / n * 1000
    return {**{f"recall@{k}": hits[k] / n for k in ks}, "MRR": rr / n, "ms/query": round(dt, 2), "n": n}

if __name__ == "__main__":
    data = load_dataset()
    print(f"ContinuityOS recall benchmark — {len(data)} labeled pairs\n")
    res = evaluate(HashingEmbedder(), data)
    print("HashingEmbedder (default, offline):")
    for k, v in res.items():
        print(f"  {k:12} {v:.3f}" if isinstance(v, float) else f"  {k:12} {v}")
    print("\nTo compare a real model:  evaluate(lambda t: model.encode(t, normalize_embeddings=True).tolist(), data)")
    print("To publish comparable numbers: replace load_dataset() with LoCoMo / LongMemEval.")
