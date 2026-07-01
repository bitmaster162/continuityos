"""Fork-aware continuity — pairs ContinuityOS with sandbox fork-runtimes (e.g. forkd,
github.com/deeplethe/forkd, Firecracker microVM fan-out).

forkd forks the *compute* (copy-on-write RAM of a warm microVM). ContinuityOS forks the
*mind*: when an agent branches N children, each child should inherit the parent's canon,
frontiers, open loops and last checkpoint — not just the process memory. Otherwise 100
forked agents share the parent's address space but drift on *decisions*.

Model (mirrors forkd fork / BRANCH):
  snapshot(parent) -> portable child DB   # "checkpoint at branch time" (copy-on-write mind)
  child(snapshot)  -> Memory              # child boots warm, inherits parent state
  merge_back(...)  -> reconcile diffs      # children converge; new memories folded up (deduped)

The store is a single SQLite file, so a snapshot is an atomic SQLite backup — cheap, and it
composes with forkd's own snapshot chains. Hook points: call snapshot() right before
forkd `branch_sandbox`; have each child call child() on boot; call merge_back() on join.
"""
from __future__ import annotations
import os, sqlite3, time
from typing import Optional, Callable
from .memory import Memory


def fork_point(memory: Memory) -> int:
    """Highest memory id in the parent right now — the boundary for merge_back."""
    row = memory.store.con.execute("SELECT COALESCE(MAX(id),0) FROM items").fetchone()
    return int(row[0])


def snapshot(memory: Memory, dest_path: str) -> str:
    """Atomic copy-on-write of the parent's whole mind into a portable child DB.
    Uses SQLite's online backup API, so it is safe even while the parent is live."""
    memory.store.con.commit()
    dst = sqlite3.connect(dest_path)
    with dst:
        memory.store.con.backup(dst)   # atomic page-level copy
    dst.close()
    return dest_path


def child(snapshot_path: str, embedder: Optional[Callable] = None,
          semantic_weight: float = 0.6) -> Memory:
    """Boot a child agent warm on the parent's snapshot — inherits canon/loops/checkpoints."""
    if not os.path.exists(snapshot_path):
        raise FileNotFoundError(snapshot_path)
    return Memory(snapshot_path, embedder=embedder, semantic_weight=semantic_weight)


def merge_back(parent: Memory, child_mem: Memory, since_id: int = 0) -> int:
    """Fold a child's *new* memories (id > since_id at fork time) back into the parent,
    skipping exact (namespace, text) duplicates so N children converging don't spam.
    Returns how many were merged."""
    rows = child_mem.store.con.execute(
        "SELECT text, namespace, tags, meta FROM items WHERE id > ? ORDER BY id",
        (since_id,)).fetchall()
    import json as _j
    merged = 0
    for text, namespace, tags, meta in rows:
        dup = parent.store.con.execute(
            "SELECT 1 FROM items WHERE namespace=? AND text=? LIMIT 1",
            (namespace, text)).fetchone()
        if dup:
            continue
        parent.remember(text, namespace=namespace,
                        tags=_j.loads(tags) if tags else [],
                        meta=_j.loads(meta) if meta else None)
        merged += 1
    return merged
