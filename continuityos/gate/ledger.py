"""Append-only audit ledger with a hash chain. Every preflight decision is recorded;
tampering with any past event breaks verification."""
from __future__ import annotations
import sqlite3, json, time, hashlib, os
from typing import Dict, Any, List

GENESIS = "0" * 64

class Ledger:
    def __init__(self, path: str = "continuity_ledger.db"):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.con = sqlite3.connect(path)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.row_factory = sqlite3.Row
        self.con.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT,
            payload TEXT, prev_hash TEXT, hash TEXT)""")
        self.con.commit()

    def _last_hash(self) -> str:
        r = self.con.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        return r["hash"] if r else GENESIS

    def append(self, kind: str, payload: Dict[str, Any]) -> str:
        ts = time.time(); prev = self._last_hash()
        body = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        h = hashlib.sha256((prev + kind + ("%.6f" % ts) + body).encode("utf-8")).hexdigest()
        self.con.execute("INSERT INTO events(ts,kind,payload,prev_hash,hash) VALUES(?,?,?,?,?)",
                         (ts, kind, body, prev, h))
        self.con.commit()
        return h

    def verify(self) -> Dict[str, Any]:
        prev = GENESIS; n = 0
        for r in self.con.execute("SELECT * FROM events ORDER BY id"):
            h = hashlib.sha256((prev + r["kind"] + ("%.6f" % r["ts"]) + r["payload"]).encode()).hexdigest()
            if h != r["hash"] or r["prev_hash"] != prev:
                return {"ok": False, "broken_at": r["id"], "verified": n}
            prev = r["hash"]; n += 1
        return {"ok": True, "verified": n}

    def export(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self.con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r["id"], "ts": r["ts"], "kind": r["kind"],
                 "payload": json.loads(r["payload"]), "hash": r["hash"][:12]} for r in rows]
