"""LoCoMo retrieval benchmark for ContinuityOS.

LoCoMo (Long Conversational Memory) = 10 long multi-session dialogues with QA
pairs whose answers cite evidence turns. We adapt it to a *retrieval* benchmark:
ingest every dialogue turn as a memory, then for each question measure whether
recall() surfaces the gold evidence turn(s) within top-k (recall@k, MRR).

USAGE
  1) Get the dataset: download `locomo10.json` from the LoCoMo repo
     (github.com/snap-research/locomo, file data/locomo10.json) and drop it at
     bench/data/locomo10.json
  2) Run:  python bench/locomo_bench.py
  3) Optionally compare embedders by editing EMBEDDERS below.

No fabricated numbers: this prints exactly what your machine measures.
"""
from __future__ import annotations
import os, json, time, tempfile
from continuityos import Memory
from continuityos.embed import HashingEmbedder

HERE = os.path.dirname(__file__)
DATA = os.path.join(HERE, "data", "locomo10.json")

def load_locomo(path: str = DATA):
    """Parse LoCoMo json -> list of samples: {turns:[{id,text}], qa:[{q,gold:[ids]}]}.
    Defensive to minor key variations across LoCoMo releases."""
    raw = json.load(open(path, encoding="utf-8"))
    samples = raw if isinstance(raw, list) else raw.get("data", [raw])
    out = []
    for s in samples:
        conv = s.get("conversation", s)
        turns = []
        for key, val in conv.items():
            if not key.startswith("session") or not isinstance(val, list):
                continue
            for t in val:
                tid = t.get("dia_id") or t.get("id") or f"{key}:{len(turns)}"
                txt = (t.get("text") or t.get("clean_text") or t.get("utterance") or "").strip()
                spk = t.get("speaker", "")
                if txt:
                    turns.append({"id": tid, "text": (f"{spk}: {txt}" if spk else txt)})
        qa = []
        for q in s.get("qa", []):
            ev = q.get("evidence") or q.get("evidences") or []
            if isinstance(ev, str):
                ev = [ev]
            ev = [str(e) for e in ev]
            if q.get("question") and ev:
                qa.append({"q": q["question"], "gold": ev})
        if turns and qa:
            out.append({"turns": turns, "qa": qa})
    return out

def evaluate(embedder, samples, ks=(1, 3, 5, 10)):
    hits = {k: 0 for k in ks}; rr = 0.0; nq = 0; t0 = time.time()
    for s in samples:
        db = os.path.join(tempfile.mkdtemp(), "loco.db")
        m = Memory(db, embedder=embedder)
        id_by_dia = {}
        for t in s["turns"]:
            rid = m.remember(t["text"], namespace="facts", meta={"dia": t["id"]})
            id_by_dia[t["id"]] = rid
        gold_rids_all = set(id_by_dia.values())
        for q in s["qa"]:
            gold = {id_by_dia[g] for g in q["gold"] if g in id_by_dia}
            if not gold:
                continue
            nq += 1
            ranked = [h.id for h in m.recall(q["q"], k=max(ks))]
            for k in ks:
                if gold & set(ranked[:k]):
                    hits[k] += 1
            # MRR: first rank that hits any gold
            rank = next((i + 1 for i, rid in enumerate(ranked) if rid in gold), None)
            if rank:
                rr += 1.0 / rank
    dt = (time.time() - t0)
    return {**{f"recall@{k}": (hits[k] / nq if nq else 0) for k in ks},
            "MRR": (rr / nq if nq else 0), "questions": nq, "sec": round(dt, 1)}

EMBEDDERS = [("HashingEmbedder (default)", HashingEmbedder())]
try:
    from continuityos.embedders import FastEmbedEmbedder
    EMBEDDERS.append(("FastEmbed bge-small [fast]", FastEmbedEmbedder()))
except Exception:
    pass

if __name__ == "__main__":
    if not os.path.exists(DATA):
        print(f"Dataset not found at {DATA}\n"
              "Download locomo10.json from github.com/snap-research/locomo (data/locomo10.json) "
              "and place it there, then re-run.")
        raise SystemExit(0)
    samples = load_locomo()
    print(f"LoCoMo: {len(samples)} dialogues, "
          f"{sum(len(s['turns']) for s in samples)} turns, "
          f"{sum(len(s['qa']) for s in samples)} QA pairs\n")
    for name, emb in EMBEDDERS:
        r = evaluate(emb, samples)
        print(name + ":")
        for k, v in r.items():
            print(f"  {k:12} {v:.3f}" if isinstance(v, float) else f"  {k:12} {v}")
        print()
