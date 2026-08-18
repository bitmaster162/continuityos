from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, FrozenSet, Iterator, Mapping, Optional
import hashlib
import json
import math
import sqlite3
import threading
import time
import uuid

from ..canon import canonical_json, sha256_obj
from ..errors import EvidenceError
from .models import ChainHead, EventRecord, VerifyResult

EVENT_SCHEMA = "sct.event/v1"

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS event (
    seq INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    ts REAL NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    CHECK (json_valid(payload)),
    CHECK (ts > 0)
);
CREATE INDEX IF NOT EXISTS ix_event_kind_seq ON event(kind, seq);
CREATE INDEX IF NOT EXISTS ix_event_ts ON event(ts);
CREATE TRIGGER IF NOT EXISTS trg_event_no_update BEFORE UPDATE ON event
BEGIN SELECT RAISE(ABORT, 'event table is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_event_no_delete BEFORE DELETE ON event
BEGIN SELECT RAISE(ABORT, 'event table is append-only'); END;
"""


def _event_body(seq: int, kind: str, ts: float, payload: Mapping[str, Any], prev_hash: Optional[str]) -> dict[str, Any]:
    return {
        "schema": EVENT_SCHEMA,
        "seq": seq,
        "kind": kind,
        "ts": ts,
        "payload": payload,
        "prev_hash": prev_hash,
    }


def _uuid7ish(ts: float) -> str:
    millis = int(ts * 1000)
    suffix = uuid.uuid4().hex[12:]
    return f"{millis:012x}-7000-4000-8000-{suffix[:12]}"


class SQLiteEvidenceStore:
    """Canonical local SCT Evidence Store with O(1)-amortized append."""

    def __init__(self, path: str | Path, *, blob_root: str | Path | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.blob_root = Path(blob_root) if blob_root is not None else self.path.with_suffix(".blobs")
        self.blob_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('store_contract_version','sct.evidence-store/v1')")
        self._tx_depth = 0

    def close(self) -> None:
        self._conn.close()

    def capabilities(self) -> FrozenSet[str]:
        return frozenset({"blob", "transaction", "stream_query", "concurrent_append"})

    @contextmanager
    def transaction(self):
        with self._lock:
            if self._tx_depth:
                self._tx_depth += 1
                try:
                    yield
                finally:
                    self._tx_depth -= 1
                return
            self._conn.execute("BEGIN IMMEDIATE")
            self._tx_depth = 1
            try:
                yield
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")
            finally:
                self._tx_depth = 0

    def head(self) -> ChainHead:
        row = self._conn.execute("SELECT seq,event_hash FROM event ORDER BY seq DESC LIMIT 1").fetchone()
        return ChainHead(0, None) if row is None else ChainHead(int(row["seq"]), str(row["event_hash"]))

    def _require_r13_case_open_admission_if_active(self) -> None:
        active = self._conn.execute(
            "SELECT 1 FROM event WHERE kind='R13_PRECASE_PROTOCOL_AMENDED' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if active is None:
            return
        qualification = self._conn.execute(
            "SELECT payload FROM event WHERE kind='R13_QUALIFICATION_PASSED' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        baseline = self._conn.execute(
            "SELECT payload FROM event WHERE kind='R13_BASELINE_SPEC_SEALED' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        authorization = self._conn.execute(
            "SELECT payload FROM event WHERE kind='CASE001_ENROLLMENT_AUTHORIZED' "
            "AND json_extract(payload,'$.protocol')='R13' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if qualification is None or baseline is None or authorization is None:
            raise EvidenceError(
                "R13_PRECASE_ADMISSION_BLOCKED: scientific PASS, sealed Arm B baseline, and exact owner authorization required"
            )
        q = json.loads(qualification["payload"])
        b = json.loads(baseline["payload"])
        a = json.loads(authorization["payload"])
        if (
            a.get("qualification_sha256") != q.get("qualification_sha256")
            or q.get("baseline_manifest_sha256") != b.get("baseline_manifest_sha256")
            or q.get("execution_authority") != "NONE"
            or a.get("execution_authority") != "NONE"
            or a.get("can_execute") is not False
        ):
            raise EvidenceError("R13_PRECASE_ADMISSION_BLOCKED: R13 admission bindings are invalid")
        if not self.verify().ok:
            raise EvidenceError("R13_PRECASE_ADMISSION_BLOCKED: Evidence Store verification failed")

    def append(self, kind: str, payload: Mapping[str, Any], *, ts: Optional[float] = None) -> EventRecord:
        if not isinstance(kind, str) or not kind.strip():
            raise EvidenceError("kind must be a non-empty string")
        if not isinstance(payload, Mapping):
            raise EvidenceError("payload must be a mapping")
        event_ts = time.time() if ts is None else float(ts)
        if not math.isfinite(event_ts) or event_ts <= 0:
            raise EvidenceError("ts must be a positive finite number")
        payload_obj = json.loads(canonical_json(dict(payload)))
        with self._lock:
            if kind.strip() == "CASE_FROZEN":
                self._require_r13_case_open_admission_if_active()
            managed = self._tx_depth == 0
            if managed:
                self._conn.execute("BEGIN IMMEDIATE")
            try:
                head = self.head()
                seq = head.seq + 1
                body = _event_body(seq, kind.strip(), event_ts, payload_obj, head.event_hash)
                event_hash = sha256_obj(body)
                event_id = _uuid7ish(event_ts)
                self._conn.execute(
                    "INSERT INTO event(seq,event_id,kind,ts,payload,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?)",
                    (seq, event_id, kind.strip(), event_ts, canonical_json(payload_obj), head.event_hash, event_hash),
                )
                if managed:
                    self._conn.execute("COMMIT")
            except Exception:
                if managed:
                    self._conn.execute("ROLLBACK")
                raise
        return EventRecord(seq, event_id, kind.strip(), event_ts, payload_obj, head.event_hash, event_hash)

    @staticmethod
    def _record(row: sqlite3.Row) -> EventRecord:
        return EventRecord(
            seq=int(row["seq"]), event_id=str(row["event_id"]), kind=str(row["kind"]),
            ts=float(row["ts"]), payload=json.loads(row["payload"]),
            prev_hash=row["prev_hash"], event_hash=str(row["event_hash"]),
        )

    def get(self, event_id: str) -> Optional[EventRecord]:
        row = self._conn.execute("SELECT * FROM event WHERE event_id=?", (event_id,)).fetchone()
        return None if row is None else self._record(row)

    def query(self, *, kind: Optional[str] = None, kinds: Optional[FrozenSet[str]] = None,
              since_seq: int = 0, until_seq: Optional[int] = None,
              limit: Optional[int] = None) -> Iterator[EventRecord]:
        if kind is not None and kinds is not None:
            raise EvidenceError("use kind or kinds, not both")
        sql = "SELECT * FROM event WHERE seq > ?"
        args: list[Any] = [int(since_seq)]
        if until_seq is not None:
            sql += " AND seq <= ?"; args.append(int(until_seq))
        if kind is not None:
            sql += " AND kind = ?"; args.append(kind)
        elif kinds:
            qs = ",".join("?" for _ in kinds)
            sql += f" AND kind IN ({qs})"; args.extend(sorted(kinds))
        sql += " ORDER BY seq ASC"
        if limit is not None:
            sql += " LIMIT ?"; args.append(int(limit))
        cur = self._conn.execute(sql, tuple(args))
        for row in cur:
            yield self._record(row)

    def verify(self, *, from_seq: int = 1, to_seq: Optional[int] = None) -> VerifyResult:
        if from_seq < 1:
            raise EvidenceError("from_seq must be >= 1")
        prev_hash = None
        if from_seq > 1:
            row = self._conn.execute("SELECT event_hash FROM event WHERE seq=?", (from_seq - 1,)).fetchone()
            if row is None:
                return VerifyResult(False, 0, None, f"missing predecessor seq {from_seq-1}")
            prev_hash = str(row["event_hash"])
        count = 0
        head_hash = prev_hash
        sql = "SELECT * FROM event WHERE seq >= ?"
        args: list[Any] = [from_seq]
        if to_seq is not None:
            sql += " AND seq <= ?"; args.append(int(to_seq))
        sql += " ORDER BY seq ASC"
        expected = from_seq
        for row in self._conn.execute(sql, tuple(args)):
            rec = self._record(row)
            if rec.seq != expected:
                return VerifyResult(False, count, head_hash, f"sequence gap at {expected}")
            if rec.prev_hash != prev_hash:
                return VerifyResult(False, count, head_hash, f"prev_hash mismatch at {rec.seq}")
            expected_hash = sha256_obj(_event_body(rec.seq, rec.kind, rec.ts, rec.payload, rec.prev_hash))
            if expected_hash != rec.event_hash:
                return VerifyResult(False, count, head_hash, f"event_hash mismatch at {rec.seq}")
            prev_hash = rec.event_hash
            head_hash = rec.event_hash
            expected += 1
            count += 1
        return VerifyResult(True, count, head_hash, None)

    def put_blob(self, data: bytes) -> str:
        if not isinstance(data, (bytes, bytearray)):
            raise EvidenceError("blob data must be bytes")
        digest = hashlib.sha256(bytes(data)).hexdigest()
        dst = self.blob_root / digest[:2] / digest[2:]
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists():
            tmp = dst.with_suffix(".tmp")
            tmp.write_bytes(bytes(data))
            tmp.replace(dst)
        return digest

    def get_blob(self, sha256: str) -> bytes:
        if len(sha256) != 64:
            raise EvidenceError("invalid blob sha256")
        path = self.blob_root / sha256[:2] / sha256[2:]
        if not path.exists():
            raise EvidenceError("blob not found")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha256:
            raise EvidenceError("blob hash mismatch")
        return data
