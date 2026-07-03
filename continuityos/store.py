"""SQLite-backed store: items + FTS5 keyword index + vector blobs.

Structural layer = `namespace` (folder-like: identity / projects / rules / ...)
and free-form `tags`. Keyword layer = FTS5. Semantic layer = float32 vectors.
Everything local, single file, zero external services.
"""
from __future__ import annotations
import sqlite3, json, time, struct, os, threading
from typing import List, Optional, Dict, Any

def _now() -> float:
    return time.time()

def pack_vec(v: List[float]) -> bytes:
    return struct.pack("<%df" % len(v), *v)

def unpack_vec(b: bytes) -> List[float]:
    return list(struct.unpack("<%df" % (len(b) // 4), b))

class Store:
    def __init__(self, path: str = "continuityos.db"):
        self.path = path
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        # check_same_thread=False + a write lock: the HTTP API serves from worker
        # threads (ThreadingHTTPServer); WAL keeps readers non-blocking and adds
        # crash resilience for the memory DB.
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        try:
            self.con.execute("PRAGMA journal_mode=WAL")
            self.con.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.OperationalError:
            pass  # e.g. some network filesystems; correctness unaffected
        self._init()

    def _init(self):
        c = self.con
        c.execute("""CREATE TABLE IF NOT EXISTS items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            namespace TEXT NOT NULL DEFAULT 'default',
            text TEXT NOT NULL,
            tags TEXT NOT NULL DEFAULT '[]',
            meta TEXT NOT NULL DEFAULT '{}',
            vec BLOB,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_items_ns ON items(namespace)")
        # FTS5 mirror for keyword/structural search
        try:
            c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS items_fts USING fts5("
                      "text, tags, namespace, content='items', content_rowid='id')")
            self.fts = True
        except sqlite3.OperationalError:
            self.fts = False  # FTS5 not compiled in -> fall back to LIKE
        c.commit()

    def add(self, text: str, namespace: str = "default",
            tags: Optional[List[str]] = None, meta: Optional[Dict[str, Any]] = None,
            vec: Optional[List[float]] = None) -> int:
        tags = tags or []; meta = meta or {}
        ts = _now()
        with self._lock:
            return self._add_locked(text, namespace, tags, meta, vec, ts)

    def _add_locked(self, text, namespace, tags, meta, vec, ts):
        cur = self.con.execute(
            "INSERT INTO items(namespace,text,tags,meta,vec,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (namespace, text, json.dumps(tags, ensure_ascii=False),
             json.dumps(meta, ensure_ascii=False), pack_vec(vec) if vec else None, ts, ts))
        rid = cur.lastrowid
        if self.fts:
            self.con.execute("INSERT INTO items_fts(rowid,text,tags,namespace) VALUES(?,?,?,?)",
                             (rid, text, " ".join(tags), namespace))
        self.con.commit()
        return rid

    def get(self, rid: int) -> Optional[sqlite3.Row]:
        return self.con.execute("SELECT * FROM items WHERE id=?", (rid,)).fetchone()

    def update_meta(self, rid: int, meta: Dict[str, Any]) -> None:
        """Rewrite an item's meta JSON (used by bi-temporal supersede; text stays immutable)."""
        self.con.execute("UPDATE items SET meta=?, updated_at=? WHERE id=?",
                         (json.dumps(meta, ensure_ascii=False), _now(), rid))
        self.con.commit()

    def delete(self, rid: int) -> bool:
        self.con.execute("DELETE FROM items WHERE id=?", (rid,))
        if self.fts:
            self.con.execute("INSERT INTO items_fts(items_fts,rowid,text,tags,namespace) "
                             "VALUES('delete',?, '', '', '')", (rid,))
        self.con.commit()
        return True

    def namespaces(self) -> List[Dict[str, Any]]:
        rows = self.con.execute(
            "SELECT namespace, COUNT(*) n FROM items GROUP BY namespace ORDER BY n DESC").fetchall()
        return [{"namespace": r["namespace"], "count": r["n"]} for r in rows]

    def keyword_search(self, query: str, namespace: Optional[str] = None,
                       limit: int = 50) -> List[sqlite3.Row]:
        if self.fts:
            q = "SELECT i.* FROM items_fts f JOIN items i ON i.id=f.rowid WHERE items_fts MATCH ?"
            args: list = [_fts_query(query)]
            if namespace:
                q += " AND i.namespace=?"; args.append(namespace)
            q += " ORDER BY bm25(items_fts) LIMIT ?"; args.append(limit)
            try:
                return self.con.execute(q, args).fetchall()
            except sqlite3.OperationalError:
                pass
        like = "%" + query.replace("%", "") + "%"
        q = "SELECT * FROM items WHERE text LIKE ?"; args = [like]
        if namespace:
            q += " AND namespace=?"; args.append(namespace)
        q += " LIMIT ?"; args.append(limit)
        return self.con.execute(q, args).fetchall()

    def all_with_vecs(self, namespace: Optional[str] = None) -> List[sqlite3.Row]:
        q = "SELECT * FROM items WHERE vec IS NOT NULL"
        args: list = []
        if namespace:
            q += " AND namespace=?"; args.append(namespace)
        return self.con.execute(q, args).fetchall()

    def count(self) -> int:
        return self.con.execute("SELECT COUNT(*) c FROM items").fetchone()["c"]

def _fts_query(q: str) -> str:
    # make a safe OR query out of bare words (avoids FTS5 syntax errors on punctuation)
    import re
    words = re.findall(r"\w+", q, re.UNICODE)
    return " OR ".join(words) if words else q
