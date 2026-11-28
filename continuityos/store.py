"""SQLite-backed store: items + FTS5 keyword index + vector blobs.

Structural layer = `namespace` (folder-like: identity / projects / rules / ...)
and free-form `tags`. Keyword layer = FTS5. Semantic layer = float32 vectors.
Everything local, single file, zero external services.
"""
from __future__ import annotations
import sqlite3, json, time, struct, os, threading
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional, Dict, Any

from .current_effect_boundary import assert_current_effect_allowed, effective_read_only

def _now() -> float:
    return time.time()

def pack_vec(v: List[float]) -> bytes:
    return struct.pack("<%df" % len(v), *v)

def unpack_vec(b: bytes) -> List[float]:
    return list(struct.unpack("<%df" % (len(b) // 4), b))


class StoreOutcomeUnknown(RuntimeError):
    """The caller must inspect durable state through a fresh connection; no retry."""


class StoreRecoveryFailed(StoreOutcomeUnknown):
    """Rollback/release could not be verified; this Store is suspended."""

class Store:
    def __init__(self, path: str = "continuityos.db", *, read_only: bool = False):
        self._lock = threading.RLock()
        self._savepoint_serial = 0
        self._read_depth = 0
        self._suspended = False
        read_only = effective_read_only(read_only)
        self.read_only = bool(read_only)
        if read_only:
            if path == ":memory:":
                raise ValueError("read-only Store requires an existing file")
            normalized = os.path.normcase(
                os.path.realpath(os.path.abspath(os.path.expanduser(path)))
            )
            self.path = normalized
            uri = Path(normalized).as_uri() + "?mode=ro"
            self.con = sqlite3.connect(
                uri,
                uri=True,
                check_same_thread=False,
            )
            self.con.row_factory = sqlite3.Row
            self.con.execute("PRAGMA query_only=ON")
            self.fts = self.con.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type='table' AND name='items_fts'"
            ).fetchone() is not None
            return
        self.path = path
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        # check_same_thread=False + a write lock: the HTTP API serves from worker
        # threads (ThreadingHTTPServer); WAL keeps readers non-blocking and adds
        # crash resilience for the memory DB.
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
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
        # v0.9 upstream (HMOS): optional semantic key per item -> key-based find()/upsert().
        cols = {r[1] for r in c.execute("PRAGMA table_info(items)").fetchall()}
        if "key" not in cols:
            c.execute("ALTER TABLE items ADD COLUMN key TEXT")
        c.execute("CREATE INDEX IF NOT EXISTS idx_items_key ON items(namespace, key)")
        # v0.9 (A2A/MEMORY_BUS): per-(namespace,key) version for pass-by-reference pointers + OCC.
        if "version" not in {r[1] for r in c.execute("PRAGMA table_info(items)").fetchall()}:
            c.execute("ALTER TABLE items ADD COLUMN version INTEGER NOT NULL DEFAULT 0")
        # FTS5 mirror for keyword/structural search
        try:
            c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS items_fts USING fts5("
                      "text, tags, namespace, content='items', content_rowid='id')")
            self.fts = True
        except sqlite3.OperationalError:
            self.fts = False  # FTS5 not compiled in -> fall back to LIKE
        c.commit()

    def _assert_usable(self):
        if self._suspended:
            raise StoreOutcomeUnknown("MEMORY_STORE_SUSPENDED_REOPEN_AND_RECONCILE")

    def _suspend(self):
        self._suspended = True
        try:
            self.con.close()
        except Exception:
            pass

    @contextmanager
    def transaction(self):
        """Serialize one write unit across connections, preserving caller transactions.

        Nested operations use savepoints. Only a transaction opened here is
        committed here; an exception never commits a partially written item/FTS
        pair or a partially superseded fact. A failed COMMIT is propagated, not
        retried as another write. Direct transactions opened through ``con``
        remain the caller's responsibility and require exclusive, same-thread
        access until their commit/rollback. Use this context manager for shared
        Store instances.
        """
        with self._lock:
            self._assert_usable()
            assert_current_effect_allowed("memory.store.transaction")
            if self.read_only:
                raise PermissionError("MEMORY_STORE_READ_ONLY")
            if self._read_depth:
                raise PermissionError("MEMORY_WRITE_DURING_READ_SNAPSHOT")
            owned = not self.con.in_transaction
            self._savepoint_serial += 1
            savepoint = "cos_write_%d" % self._savepoint_serial
            if owned:
                self.con.execute("BEGIN IMMEDIATE")
            else:
                self.con.execute("SAVEPOINT " + savepoint)
            phase = "body"
            try:
                yield self
                if owned:
                    assert_current_effect_allowed("memory.store.commit")
                    phase = "commit"
                    self.con.commit()
                else:
                    phase = "release"
                    self.con.execute("RELEASE SAVEPOINT " + savepoint)
            except BaseException as original:
                if self._suspended:
                    raise
                try:
                    pending = self.con.in_transaction
                except Exception as recovery:
                    self._suspend()
                    raise StoreRecoveryFailed("MEMORY_TRANSACTION_STATE_UNKNOWN") from recovery
                if phase == "commit" and not pending:
                    self._suspend()
                    raise StoreOutcomeUnknown("MEMORY_COMMIT_OUTCOME_UNKNOWN_RECONCILE_NO_RETRY") from original
                try:
                    if pending:
                        if owned:
                            self.con.rollback()
                        else:
                            self.con.execute("ROLLBACK TO SAVEPOINT " + savepoint)
                            self.con.execute("RELEASE SAVEPOINT " + savepoint)
                except BaseException as recovery:
                    self._suspend()
                    raise StoreRecoveryFailed("MEMORY_ROLLBACK_UNVERIFIED_STORE_SUSPENDED") from recovery
                raise

    @contextmanager
    def read_snapshot(self):
        """One SQLite read snapshot, serialized with managed writes.

        The connection lock covers a whole composed read. A caller-owned write
        transaction is retained; a read transaction opened here ends without a
        commit. Writes through Store are prohibited inside this read scope.
        Raw caller-owned transactions require exclusive same-thread access;
        direct use of ``con`` bypasses the managed concurrency contract.
        """
        with self._lock:
            self._assert_usable()
            owned = not self.con.in_transaction
            if owned:
                self.con.execute("BEGIN")
            self._read_depth += 1
            try:
                yield self
            finally:
                self._read_depth -= 1
                try:
                    if owned and self.con.in_transaction:
                        self.con.rollback()
                except BaseException as recovery:
                    self._suspend()
                    raise StoreRecoveryFailed("MEMORY_READ_SNAPSHOT_RECOVERY_FAILED") from recovery

    def add(self, text: str, namespace: str = "default",
            tags: Optional[List[str]] = None, meta: Optional[Dict[str, Any]] = None,
            vec: Optional[List[float]] = None, key: Optional[str] = None) -> int:
        assert_current_effect_allowed("memory.store.add")
        tags = tags or []; meta = meta or {}
        ts = _now()
        with self.transaction():
            return self._add_locked(text, namespace, tags, meta, vec, ts, key)

    def _add_locked(self, text, namespace, tags, meta, vec, ts, key=None):
        assert_current_effect_allowed("memory.store.add")
        version = 0
        if key is not None:
            row = self.con.execute("SELECT MAX(version) v FROM items WHERE namespace=? AND key=?", (namespace, key)).fetchone()
            version = ((row["v"] or 0) + 1) if row else 1
        cur = self.con.execute(
            "INSERT INTO items(namespace,text,tags,meta,vec,created_at,updated_at,key,version) VALUES(?,?,?,?,?,?,?,?,?)",
            (namespace, text, json.dumps(tags, ensure_ascii=False),
             json.dumps(meta, ensure_ascii=False), pack_vec(vec) if vec else None, ts, ts, key, version))
        rid = cur.lastrowid
        if self.fts:
            self.con.execute("INSERT INTO items_fts(rowid,text,tags,namespace) VALUES(?,?,?,?)",
                             (rid, text, " ".join(tags), namespace))
        return rid

    def get(self, rid: int) -> Optional[sqlite3.Row]:
        with self._lock:
            self._assert_usable()
            return self.con.execute("SELECT * FROM items WHERE id=?", (rid,)).fetchone()

    def find_by_key(self, namespace: str, key: str) -> Optional[sqlite3.Row]:
        """Newest row for a (namespace, key). upsert() supersedes older versions, so the
        highest id is the current value; history rows keep the key for audit/replay."""
        with self._lock:
            self._assert_usable()
            return self.con.execute(
                "SELECT * FROM items WHERE namespace=? AND key=? ORDER BY id DESC LIMIT 1",
                (namespace, key)).fetchone()

    def current_version(self, namespace: str, key: str) -> int:
        """Highest version stored under (namespace, key); 0 if none. Basis for OCC."""
        with self._lock:
            self._assert_usable()
            r = self.con.execute("SELECT MAX(version) v FROM items WHERE namespace=? AND key=?", (namespace, key)).fetchone()
            return (r["v"] or 0) if r else 0

    def update_meta(self, rid: int, meta: Dict[str, Any]) -> None:
        """Rewrite an item's meta JSON (used by bi-temporal supersede; text stays immutable)."""
        assert_current_effect_allowed("memory.store.update_meta")
        with self.transaction():
            self.con.execute("UPDATE items SET meta=?, updated_at=? WHERE id=?",
                             (json.dumps(meta, ensure_ascii=False), _now(), rid))

    def close_loop(self, rid: int, *, result: str = "", proof: str = "") -> bool:
        """Close an existing loop once, retaining its text and closure evidence."""
        assert_current_effect_allowed("memory.store.close_loop")
        with self.transaction():
            row = self.get(rid)
            if row is None or row["namespace"] != "loop":
                return False
            meta = json.loads(row["meta"])
            if meta.get("open") is False or meta.get("status") == "CLOSED":
                return True
            event = {"status": "CLOSED", "closed_at": _now(),
                     "result": result, "proof": proof}
            history = list(meta.get("closure_history", []))
            history.append(dict(event))
            meta.update(event)
            meta["open"] = False
            meta["closure_history"] = history
            self.update_meta(rid, meta)
            return True

    def delete(self, rid: int) -> bool:
        assert_current_effect_allowed("memory.store.delete")
        with self.transaction():
            row = self.get(rid)
            self.con.execute("DELETE FROM items WHERE id=?", (rid,))
            if self.fts and row is not None:
                self.con.execute("INSERT INTO items_fts(items_fts,rowid,text,tags,namespace) "
                                 "VALUES('delete',?,?,?,?)",
                                 (rid, row["text"], " ".join(json.loads(row["tags"])), row["namespace"]))
        return True

    def namespaces(self) -> List[Dict[str, Any]]:
        with self._lock:
            self._assert_usable()
            rows = self.con.execute(
                "SELECT namespace, COUNT(*) n FROM items GROUP BY namespace ORDER BY n DESC").fetchall()
            return [{"namespace": r["namespace"], "count": r["n"]} for r in rows]

    def keyword_search(self, query: str, namespace: Optional[str] = None,
                       limit: Optional[int] = 50) -> List[sqlite3.Row]:
        with self._lock:
            self._assert_usable()
            return self._keyword_search_locked(query, namespace, limit)

    def _keyword_search_locked(self, query, namespace, limit):
        if self.fts:
            q = "SELECT i.* FROM items_fts f JOIN items i ON i.id=f.rowid WHERE items_fts MATCH ?"
            args: list = [_fts_query(query)]
            if namespace:
                q += " AND i.namespace=?"; args.append(namespace)
            q += " ORDER BY bm25(items_fts)"
            if limit is not None:
                q += " LIMIT ?"; args.append(limit)
            try:
                return self.con.execute(q, args).fetchall()
            except sqlite3.OperationalError:
                pass
        like = "%" + query.replace("%", "") + "%"
        q = "SELECT * FROM items WHERE text LIKE ?"; args = [like]
        if namespace:
            q += " AND namespace=?"; args.append(namespace)
        if limit is not None:
            q += " LIMIT ?"; args.append(limit)
        return self.con.execute(q, args).fetchall()

    def all_with_vecs(self, namespace: Optional[str] = None) -> List[sqlite3.Row]:
        q = "SELECT * FROM items WHERE vec IS NOT NULL"
        args: list = []
        if namespace:
            q += " AND namespace=?"; args.append(namespace)
        with self._lock:
            self._assert_usable()
            return self.con.execute(q, args).fetchall()

    def count(self) -> int:
        with self._lock:
            self._assert_usable()
            return self.con.execute("SELECT COUNT(*) c FROM items").fetchone()["c"]

def _fts_query(q: str) -> str:
    # make a safe OR query out of bare words (avoids FTS5 syntax errors on punctuation)
    import re
    words = re.findall(r"\w+", q, re.UNICODE)
    return " OR ".join(words) if words else q
