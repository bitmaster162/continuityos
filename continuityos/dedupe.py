"""ContinuityOS memory de-duplication — MinHash + SimHash LSH (pure-python, no deps).

Applies guide_lsh_deduplication: collapses near-duplicate memories into CompactDigest
records so the long-term store doesn't bloat with restated facts. Parameters match the
guide: MinHash Jaccard >= 0.55 (n_perm=128), SimHash Hamming <= 3 (strict) / <= 4 (soft).

Usage:
    from continuityos.dedupe import find_near_duplicates, compact_digest
    groups = find_near_duplicates([(m.id, m.text) for m in all_memories])
    for g in groups: digest = compact_digest(g)
Read-only by design: returns duplicate groups + digests; the caller decides what to drop.
"""
from __future__ import annotations
import re, hashlib
from typing import List, Tuple, Dict

_WORD = re.compile(r"\w+", re.UNICODE)
N_PERM = 128
JACCARD_THRESH = 0.55
HAMMING_STRICT = 3
HAMMING_SOFT = 4
_MERSENNE = (1 << 61) - 1


def _shingles(text: str, k: int = 3) -> set:
    toks = [t.lower() for t in _WORD.findall(text)]
    if len(toks) < k:
        return set(toks)
    return {" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1)}


def _h(s: str, seed: int) -> int:
    return int(hashlib.blake2b(s.encode("utf-8"), digest_size=8,
                               salt=seed.to_bytes(8, "little")).hexdigest(), 16)


def minhash(text: str, n_perm: int = N_PERM) -> Tuple[int, ...]:
    """MinHash signature (n_perm permutations)."""
    sh = _shingles(text)
    if not sh:
        return tuple([0] * n_perm)
    sig = []
    for p in range(n_perm):
        sig.append(min(_h(s, p) % _MERSENNE for s in sh))
    return tuple(sig)


def jaccard(a: Tuple[int, ...], b: Tuple[int, ...]) -> float:
    if not a or not b:
        return 0.0
    return sum(1 for x, y in zip(a, b) if x == y) / len(a)


def simhash(text: str, bits: int = 64) -> int:
    """SimHash fingerprint."""
    v = [0] * bits
    for s in _shingles(text, k=2):
        hv = _h(s, 1)
        for i in range(bits):
            v[i] += 1 if (hv >> i) & 1 else -1
    out = 0
    for i in range(bits):
        if v[i] > 0:
            out |= (1 << i)
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def find_near_duplicates(items: List[Tuple[str, str]],
                         jaccard_thresh: float = JACCARD_THRESH,
                         hamming_thresh: int = HAMMING_STRICT) -> List[List[str]]:
    """items = [(id, text), ...] -> list of duplicate groups (each a list of ids).
    Two-stage gate (guide): SimHash Hamming candidate -> MinHash Jaccard confirm."""
    sims = {i: simhash(t) for i, t in items}
    mins = {i: minhash(t) for i, t in items}
    ids = [i for i, _ in items]
    parent: Dict[str, str] = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for ai in range(len(ids)):
        for bi in range(ai + 1, len(ids)):
            a, b = ids[ai], ids[bi]
            if hamming(sims[a], sims[b]) <= hamming_thresh and \
               jaccard(mins[a], mins[b]) >= jaccard_thresh:
                union(a, b)
    groups: Dict[str, List[str]] = {}
    for i in ids:
        groups.setdefault(find(i), []).append(i)
    return [g for g in groups.values() if len(g) > 1]


def compact_digest(group_items: List[Tuple[str, str]]) -> dict:
    """Collapse a duplicate group into one CompactDigest (guide format):
    core summary = the longest/most-informative text, back-trace ids preserved."""
    canonical = max(group_items, key=lambda it: len(it[1]))
    return {
        "core_summary": canonical[1],
        "canonical_id": canonical[0],
        "back_trace_ids": [i for i, _ in group_items],
        "merged_count": len(group_items),
    }


# NOTE: LSH (MinHash/SimHash) is the NEAR-EXACT layer — it collapses the same fact
# restated with minor edits (punctuation, whitespace, a swapped word). Semantic
# paraphrases ("X causes Y" vs "Y is caused by X") are NOT near-duplicates here by
# design; those are handled by ContinuityOS vector recall. Two cheap, complementary layers.
if __name__ == "__main__":
    demo = [
        ("m1", "The arena uses GCP spot preemption which causes periodic reboots and bot flapping."),
        ("m2", "The arena uses GCP spot preemption which causes periodic reboots and bot flapping"),
        ("m3", "The arena uses GCP spot-preemption, which causes periodic reboots and bot flapping."),
        ("m4", "Grid trading is market-neutral and works best in flat regimes."),
        ("m5", "Completely unrelated note about coffee and morning routines and tea."),
    ]
    groups = find_near_duplicates(demo)
    print("duplicate groups:", groups)  # expect [['m1','m2','m3']]
    for g in groups:
        print("digest:", compact_digest([(i, t) for i, t in demo if i in g]))
