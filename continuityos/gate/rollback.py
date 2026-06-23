"""Real local rollback: snapshot affected files before a change, restore on demand.
Honest scope: local files only. Cannot undo irreversible external side effects."""
from __future__ import annotations
import os, json, time, shutil, hashlib
from typing import List, Dict, Any

SNAP_ROOT = os.path.expanduser("~/.continuityos/snapshots")

def snapshot(paths: List[str]) -> Dict[str, Any]:
    sid = hashlib.sha256(("%f%s" % (time.time(), ",".join(paths))).encode()).hexdigest()[:16]
    d = os.path.join(SNAP_ROOT, sid); os.makedirs(d, exist_ok=True)
    saved = []
    for i, p in enumerate(paths or []):
        pe = os.path.expanduser(p)
        if os.path.isfile(pe):
            dst = os.path.join(d, "%d_%s" % (i, os.path.basename(pe)))
            try:
                shutil.copy2(pe, dst); saved.append({"orig": pe, "snap": dst})
            except Exception:
                pass
    json.dump({"id": sid, "ts": time.time(), "files": saved}, open(os.path.join(d, "manifest.json"), "w"))
    return {"id": sid, "saved": len(saved), "restorable": bool(saved)}

def restore(sid: str) -> Dict[str, Any]:
    man = os.path.join(SNAP_ROOT, sid, "manifest.json")
    if not os.path.exists(man):
        return {"ok": False, "error": "snapshot not found"}
    m = json.load(open(man)); n = 0
    for f in m["files"]:
        try:
            shutil.copy2(f["snap"], f["orig"]); n += 1
        except Exception:
            pass
    return {"ok": True, "restored": n, "id": sid}
