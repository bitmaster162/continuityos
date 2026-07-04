"""cos epoch — a git-like DAG of epoch results, recorded append-only in memory.

Each epoch's results are a *commit*: a node with a parent (or a fork point), a
branch, an epoch number, and a metrics dict. Branches fork like git. Nothing is
ever deleted (append-only — the same tamper-evident model as the rest of
ContinuityOS). Export to JSON for the Three.js InstancedMesh viewer, or read it
back like ``git log``.

    cos epoch commit -b main -l "arena gen 12" -m wr=0.375 -m expectancy=-0.258
    cos epoch branch experiment --from main     # fork a new branch at main's HEAD
    cos epoch commit -b experiment -l "looser stop" -m wr=0.41
    cos epoch log
    cos epoch graph --out epoch_graph.json       # {nodes, edges, branches} for the viz

stdlib-only, deterministic.
"""
from __future__ import annotations
import json, time
from typing import Any, Dict, List, Optional


class EpochGraph:
    NS = "epoch"

    def __init__(self, memory):
        self.m = memory

    # ---- read ----
    def _records(self) -> List[Dict[str, Any]]:
        rows = self.m.store.all_with_vecs(namespace=self.NS)
        out = []
        for r in rows:
            meta = json.loads(r["meta"])
            out.append({"id": r["id"], "text": r["text"], **meta})
        out.sort(key=lambda c: c["id"])
        return out

    def _commits(self) -> List[Dict[str, Any]]:
        return [c for c in self._records() if c.get("epoch_kind") == "commit"]

    def _branch_forks(self) -> Dict[str, Optional[int]]:
        f = {}
        for r in self._records():
            if r.get("epoch_kind") == "branch":
                f[r["branch"]] = r.get("from")
        return f

    def head(self, branch: str) -> Optional[int]:
        cs = [c for c in self._commits() if c["branch"] == branch]
        return cs[-1]["id"] if cs else None

    def _fork_parent(self, branch: str) -> Optional[int]:
        return self._branch_forks().get(branch)

    def branches(self) -> List[str]:
        bs = {c["branch"] for c in self._commits()} | set(self._branch_forks())
        return sorted(bs) or ["main"]

    # ---- write ----
    def branch(self, name: str, from_branch: str = "main", from_commit: Optional[int] = None) -> int:
        parent = from_commit if from_commit is not None else self.head(from_branch)
        meta = {"epoch_kind": "branch", "branch": name, "from": parent,
                "from_branch": from_branch, "ts": time.time()}
        return self.m.remember("branch %s from %s" % (name, from_branch),
                               namespace=self.NS, tags=["epoch", "branch", name], meta=meta)

    def commit(self, branch: str = "main", label: str = "",
               metrics: Optional[Dict[str, float]] = None, parent: Optional[int] = None) -> int:
        if parent is None:
            parent = self.head(branch)
            if parent is None:
                parent = self._fork_parent(branch)     # first commit on a forked branch
        n = 1 + max([c["epoch"] for c in self._commits() if c["branch"] == branch], default=0)
        meta = {"epoch_kind": "commit", "branch": branch, "parent": parent, "epoch": n,
                "metrics": metrics or {}, "label": label, "ts": time.time()}
        return self.m.remember(label or ("%s#%d" % (branch, n)),
                               namespace=self.NS, tags=["epoch", branch], meta=meta)

    # ---- export ----
    def to_graph(self) -> Dict[str, Any]:
        cs = self._commits()
        nodes = [{"id": c["id"], "branch": c["branch"], "epoch": c["epoch"],
                  "label": c["label"], "metrics": c.get("metrics", {}), "ts": c["ts"]} for c in cs]
        edges = [{"source": c["parent"], "target": c["id"]}
                 for c in cs if c.get("parent") is not None]
        return {"nodes": nodes, "edges": edges, "branches": self.branches(),
                "generated": time.time()}

    def log(self, branch: Optional[str] = None) -> List[Dict[str, Any]]:
        cs = self._commits()
        if branch:
            cs = [c for c in cs if c["branch"] == branch]
        return list(reversed(cs))
