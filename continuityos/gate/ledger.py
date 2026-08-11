"""Append-only audit ledger with a hash chain. Every preflight decision is recorded;
tampering with any past event breaks verification."""
from __future__ import annotations
import sqlite3, json, time, hashlib, os
from typing import Dict, Any, List

GENESIS = "0" * 64
HASH_SCHEME = "sha256-prev-kind-ts6-payload-v1"

class Ledger:
    def __init__(self, path: str = "continuity_ledger.db"):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.con = sqlite3.connect(path, timeout=30.0)
        self.con.execute("PRAGMA busy_timeout=30000")
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
        body = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        try:
            # Serialize head-read + append across independent processes/connections.
            self.con.execute("BEGIN IMMEDIATE")
            ts = time.time()
            prev = self._last_hash()
            h = hashlib.sha256((prev + kind + ("%.6f" % ts) + body).encode("utf-8")).hexdigest()
            self.con.execute(
                "INSERT INTO events(ts,kind,payload,prev_hash,hash) VALUES(?,?,?,?,?)",
                (ts, kind, body, prev, h),
            )
            self.con.commit()
            return h
        except Exception:
            self.con.rollback()
            raise

    def verify(self) -> Dict[str, Any]:
        prev = GENESIS; n = 0
        for r in self.con.execute("SELECT * FROM events ORDER BY id"):
            h = hashlib.sha256((prev + r["kind"] + ("%.6f" % r["ts"]) + r["payload"]).encode("utf-8")).hexdigest()
            if h != r["hash"] or r["prev_hash"] != prev:
                return {"ok": False, "broken_at": r["id"], "verified": n}
            prev = r["hash"]; n += 1
        return {"ok": True, "verified": n}

    def export(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self.con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._event_dict(r) for r in rows]

    @staticmethod
    def _event_dict(r) -> Dict[str, Any]:
        return {
            "id": r["id"],
            "ts": r["ts"],
            "ts_text": "%.6f" % r["ts"],
            "kind": r["kind"],
            "payload": json.loads(r["payload"]),
            "payload_json": r["payload"],
            "prev_hash": r["prev_hash"],
            "hash": r["hash"],
            "hash_scheme": HASH_SCHEME,
        }

    def event(self, event_hash: str):
        row = self.con.execute(
            "SELECT * FROM events WHERE hash=? LIMIT 1", (event_hash,)
        ).fetchone()
        return self._event_dict(row) if row is not None else None

    def close(self) -> None:
        self.con.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
