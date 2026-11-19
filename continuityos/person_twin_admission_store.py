"""Durable, synthetic-qualified R3 admission in an existing Memory SQLite file.

This is a trusted-host storage adapter, not an authority issuer. It persists the
actual R3 receipt and verifies it after COMMIT through a new read-only connection.
Fresh consent, time, policy, session and disclosure authority remain external.
No CLI, running database, R3/R4 implementation or current-mode ceiling is changed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import stat
import uuid
from typing import Any, Callable, Mapping

from .current_effect_boundary import assert_current_effect_allowed
from .person_twin_admission_contracts import validate_person_twin_identity
from .person_twin_admission_coordinator import (
    AdmissionStoreConflict, AdmissionStoreError, PersonTwinAdmissionCoordinator,
)
from .person_twin_authority_replay import _current_admission
from .person_twin_privacy_provenance import validate_person_twin_record
from .person_twin_r21h_evidence import MEMORY_BINDING_SCHEMA, _require_current_meta

SCHEMA = "continuityos.person-twin.durable-admission/v1"
MAX_RECORD_BYTES = 1024 * 1024  # bounded lab input, not a calibrated production limit
_CEILING = dict(production_admission_status="NOT_PRODUCTION_ADMITTED",
                execution_authority="NONE", can_execute=False, can_trade=False,
                capital_permission="DENY")
_DDL = (
    "CREATE TABLE person_admission_meta (slot INTEGER PRIMARY KEY CHECK(slot=1), schema_id TEXT NOT NULL)",
    "CREATE TABLE person_admission_candidates (twin_key TEXT NOT NULL, candidate_id TEXT NOT NULL, candidate BLOB NOT NULL, candidate_hash TEXT NOT NULL, anchors BLOB NOT NULL, anchors_hash TEXT NOT NULL, binding BLOB NOT NULL, binding_hash TEXT NOT NULL, PRIMARY KEY(twin_key,candidate_id))",
    "CREATE TABLE person_admission_publications (publication_id TEXT PRIMARY KEY, twin_key TEXT NOT NULL, candidate_id TEXT NOT NULL, pointer BLOB NOT NULL, pointer_hash TEXT NOT NULL, receipt BLOB NOT NULL, receipt_hash TEXT NOT NULL, binding_hash TEXT NOT NULL, previous_publication_id TEXT, UNIQUE(publication_id,twin_key,pointer_hash), FOREIGN KEY(twin_key,candidate_id) REFERENCES person_admission_candidates(twin_key,candidate_id))",
    "CREATE TABLE person_admission_current (twin_key TEXT PRIMARY KEY, publication_id TEXT NOT NULL UNIQUE, pointer BLOB NOT NULL, pointer_hash TEXT NOT NULL, FOREIGN KEY(publication_id,twin_key,pointer_hash) REFERENCES person_admission_publications(publication_id,twin_key,pointer_hash) DEFERRABLE INITIALLY DEFERRED)",
)
_TABLES = tuple(sql.split()[2] for sql in _DDL)


class DurableAdmissionError(AdmissionStoreError):
    """Fixed-code error; no protected source text or filesystem path is returned."""


def _canonical(value: Any) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"), allow_nan=False).encode("utf-8")
    if not 0 < len(raw) <= MAX_RECORD_BYTES:
        raise DurableAdmissionError("ADMISSION_RECORD_SIZE_INVALID")
    return raw


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _decode(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RECORD_BYTES:
        raise DurableAdmissionError("ADMISSION_BYTES_INVALID")
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or _canonical(value) != raw:
            raise ValueError()
        return value
    except Exception:
        raise DurableAdmissionError("ADMISSION_CANONICAL_JSON_INVALID") from None


def _identity(value: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    try:
        identity = _decode(_canonical(dict(value)))
        validate_person_twin_identity(identity)
        key = _hash(_canonical({k: identity[k] for k in
                               ("tenant_id", "twin_id", "identity_fingerprint")}))
        return identity, key
    except Exception:
        raise DurableAdmissionError("ADMISSION_IDENTITY_INVALID") from None


def _direct_file(path: Path) -> tuple[int, int]:
    try:
        for member in (path, *path.parents):
            info = member.lstat()
            if member.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError()
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError()
        return info.st_dev, info.st_ino
    except Exception:
        raise DurableAdmissionError("ADMISSION_DB_PATH_INVALID") from None


def _connect(path: Path, read_only: bool, timeout: float) -> sqlite3.Connection:
    before = _direct_file(path)
    con = None
    try:
        con = sqlite3.connect(path.as_uri() + ("?mode=ro" if read_only else "?mode=rw"),
                              uri=True, isolation_level=None, timeout=timeout)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA trusted_schema=OFF")
        if read_only:
            con.execute("PRAGMA query_only=ON")
        else:
            con.execute("PRAGMA synchronous=FULL")
        if con.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ValueError()
        if not read_only and con.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise ValueError()
        if before != _direct_file(path):
            raise ValueError()
        row = con.execute("SELECT type FROM sqlite_master WHERE name='items'").fetchone()
        if row is None or row[0] != "table":
            raise ValueError()
        columns = {r[1] for r in con.execute("PRAGMA table_info(items)")}
        if not {"id", "namespace", "text", "meta"}.issubset(columns):
            raise ValueError()
        return con
    except Exception:
        if con is not None:
            con.close()
        raise DurableAdmissionError("ADMISSION_DB_OPEN_FAILED") from None


def _schema(con: sqlite3.Connection) -> None:
    if con.execute("PRAGMA foreign_keys").fetchone()[0] != 1 or con.execute("PRAGMA trusted_schema").fetchone()[0] != 0:
        raise DurableAdmissionError("ADMISSION_CONNECTION_SETTINGS_CHANGED")
    if con.execute("PRAGMA query_only").fetchone()[0] == 0 and con.execute("PRAGMA synchronous").fetchone()[0] != 2:
        raise DurableAdmissionError("ADMISSION_DURABILITY_SETTING_CHANGED")
    for name, expected in zip(_TABLES, _DDL):
        row = con.execute("SELECT type,sql FROM sqlite_master WHERE name=?", (name,)).fetchone()
        if row is None or row[0] != "table" or row[1] != expected:
            raise DurableAdmissionError("ADMISSION_SCHEMA_MISMATCH")
        if con.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (name,)).fetchone():
            raise DurableAdmissionError("ADMISSION_SCHEMA_TRIGGER_DENIED")
    rows = con.execute("SELECT slot,schema_id FROM person_admission_meta").fetchall()
    if len(rows) != 1 or tuple(rows[0]) != (1, SCHEMA):
        raise DurableAdmissionError("ADMISSION_SCHEMA_VERSION_MISMATCH")


@dataclass(frozen=True)
class AdmissionSnapshot:
    """Verified stored bytes, not a fresh authorization or a signed attestation."""
    publication_id: str
    candidate_bytes: bytes
    pointer_bytes: bytes
    receipt_bytes: bytes
    anchors_bytes: bytes
    binding_bytes: bytes

    @property
    def candidate(self) -> dict[str, Any]:
        return _decode(self.candidate_bytes)

    @property
    def pointer(self) -> dict[str, Any]:
        return _decode(self.pointer_bytes)

    @property
    def receipt(self) -> dict[str, Any]:
        return _decode(self.receipt_bytes)

    @property
    def anchors(self) -> dict[str, Any]:
        return _decode(self.anchors_bytes)

    @property
    def binding(self) -> dict[str, Any]:
        return _decode(self.binding_bytes)


class _Readback:
    """Already read SQLite snapshot used by the unchanged R4 structural validator."""
    def __init__(self, candidate_id: str, candidate: bytes, pointer: bytes):
        self.cid, self.candidate, self.pointer = candidate_id, candidate, pointer

    def read_candidate_bytes(self, candidate_id: str) -> bytes | None:
        return self.candidate if candidate_id == self.cid else None

    def read_current_pointer_bytes(self) -> bytes:
        return self.pointer


class PersonTwinAdmissionStore:
    """One thread-owned connection; independent writers use independent instances.

    Constructor is read-only by default and never creates a file or a schema.
    Only admit() can invoke the R3 write callbacks. Direct promotion is rejected.
    """
    def __init__(self, path: str | Path, *, identity: Mapping[str, Any],
                 read_only: bool = True, timeout: float = 2.0):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 <= timeout <= 10:
            raise DurableAdmissionError("ADMISSION_TIMEOUT_INVALID")
        if type(read_only) is not bool:
            raise DurableAdmissionError("ADMISSION_MODE_INVALID")
        self.identity, self.twin_key = _identity(identity)
        self.path = Path(path).absolute()
        self.read_only, self.timeout = read_only, float(timeout)
        if not read_only:
            assert_current_effect_allowed("person.admission.open_writer")
        self._file_identity = _direct_file(self.path)
        self._con = _connect(self.path, read_only, self.timeout)
        try:
            _schema(self._con)
        except Exception:
            self._con.close()
            raise DurableAdmissionError("ADMISSION_SCHEMA_UNAVAILABLE") from None
        self._phase = None
        self._active = None
        self._expected_publication = None
        self._next_publication = None
        self._candidate_committed = False
        self._candidate_commit_state = "NOT_ATTEMPTED"
        self._suspended = False
        self._commit_state = "NOT_ATTEMPTED"

    @classmethod
    def initialize(cls, path: str | Path) -> None:
        """Explicit schema preparation only, in an existing Memory database."""
        assert_current_effect_allowed("person.admission.initialize")
        con = _connect(Path(path).absolute(), False, 2.0)
        try:
            con.execute("BEGIN IMMEDIATE")
            existing = [con.execute("SELECT 1 FROM sqlite_master WHERE name=?", (n,)).fetchone()
                        for n in _TABLES]
            if not any(existing):
                for ddl in _DDL:
                    con.execute(ddl)
                con.execute("INSERT INTO person_admission_meta VALUES(1,?)", (SCHEMA,))
            _schema(con)
            assert_current_effect_allowed("person.admission.initialize_commit")
            con.execute("COMMIT")
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise DurableAdmissionError("ADMISSION_SCHEMA_INITIALIZE_FAILED") from None
        finally:
            con.close()

    def __enter__(self) -> PersonTwinAdmissionStore:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        self._con.close()

    def _current_row(self):
        return self._con.execute("SELECT * FROM person_admission_current WHERE twin_key=?",
                                 (self.twin_key,)).fetchone()

    def _row_binding(self, record, anchors, memory_id, namespace, *, at=None):
        if type(memory_id) is not int or memory_id < 1 or type(namespace) is not str or not namespace.strip():
            raise DurableAdmissionError("ADMISSION_MEMORY_BINDING_INVALID")
        row = self._con.execute("SELECT id,namespace,text,meta FROM items WHERE id=?", (memory_id,)).fetchone()
        source = anchors["source_record"]
        text = source["payload"]["text"]
        if row is None or row["namespace"] != namespace or row["text"] != text or not isinstance(text, str) or not text.strip():
            raise DurableAdmissionError("ADMISSION_MEMORY_SOURCE_MISMATCH")
        if at is not None:
            _require_current_meta(row["meta"], at)
        return dict(schema=SCHEMA + "/memory-binding", twin_key=self.twin_key,
                    memory_id=memory_id, namespace=namespace, candidate_id=record["id"],
                    candidate_sha256=_hash(_canonical(record)),
                    source_record_id=source["id"], source_content_hash=source["content_hash"],
                    text_sha256=_hash(text.encode("utf-8")), anchors_sha256=_hash(_canonical(anchors)))

    def _candidate_row(self, candidate_id):
        row = self._con.execute("SELECT * FROM person_admission_candidates WHERE twin_key=? AND candidate_id=?",
                                 (self.twin_key, candidate_id)).fetchone()
        if row is None:
            return None
        for payload, digest in (("candidate", "candidate_hash"), ("anchors", "anchors_hash"), ("binding", "binding_hash")):
            _decode(row[payload])
            if _hash(row[payload]) != row[digest]:
                raise DurableAdmissionError("ADMISSION_STORED_HASH_MISMATCH")
        record, anchors, binding = (_decode(row[k]) for k in ("candidate", "anchors", "binding"))
        if set(anchors) != {"identity", "consent_receipt", "source_record", "purpose"} or anchors["identity"] != self.identity:
            raise DurableAdmissionError("ADMISSION_STORED_IDENTITY_MISMATCH")
        validate_person_twin_record(record, identity=self.identity,
                                   consent_receipt=anchors["consent_receipt"], source_record=anchors["source_record"])
        if record["id"] != candidate_id:
            raise DurableAdmissionError("ADMISSION_STORED_CANDIDATE_MISMATCH")
        expected = self._row_binding(record, anchors, binding["memory_id"], binding["namespace"])
        if binding != expected:
            raise DurableAdmissionError("ADMISSION_STORED_BINDING_MISMATCH")
        return row

    def read_candidate_bytes(self, candidate_id: str) -> bytes | None:
        try:
            row = self._candidate_row(candidate_id)
            return None if row is None else row["candidate"]
        except Exception:
            raise DurableAdmissionError("ADMISSION_CANDIDATE_READ_FAILED") from None

    def _snapshot(self) -> AdmissionSnapshot | None:
        current = self._current_row()
        if current is None:
            return None
        pub = self._con.execute("SELECT * FROM person_admission_publications WHERE publication_id=? AND twin_key=?",
                                 (current["publication_id"], self.twin_key)).fetchone()
        if pub is None or current["pointer"] != pub["pointer"] or current["pointer_hash"] != pub["pointer_hash"]:
            raise DurableAdmissionError("ADMISSION_PUBLICATION_INCOMPLETE")
        row = self._candidate_row(pub["candidate_id"])
        if row is None or pub["binding_hash"] != row["binding_hash"]:
            raise DurableAdmissionError("ADMISSION_PUBLICATION_BINDING_MISMATCH")
        pointer, receipt = _decode(pub["pointer"]), _decode(pub["receipt"])
        if _hash(pub["pointer"]) != pub["pointer_hash"] or _hash(pub["receipt"]) != pub["receipt_hash"]:
            raise DurableAdmissionError("ADMISSION_PUBLICATION_HASH_MISMATCH")
        if receipt.get("history") != ["STAGED", "VALIDATED", "COMMITTED_NOT_CURRENT", "POSTVERIFY_PASS", "CURRENT"]:
            raise DurableAdmissionError("ADMISSION_RECEIPT_HISTORY_INVALID")
        if receipt.get("reason") != "EXACT_POSTVERIFIED_CANDIDATE_PROMOTED_BY_OCC":
            raise DurableAdmissionError("ADMISSION_RECEIPT_REASON_INVALID")
        previous = pub["previous_publication_id"]
        previous_hash = None
        if previous is not None:
            old = self._con.execute("SELECT pointer_hash FROM person_admission_publications WHERE publication_id=? AND twin_key=?",
                                     (previous, self.twin_key)).fetchone()
            if old is None or previous == pub["publication_id"]:
                raise DurableAdmissionError("ADMISSION_PREDECESSOR_MISMATCH")
            previous_hash = old[0]
        if receipt.get("expected_pointer_sha256") != previous_hash:
            raise DurableAdmissionError("ADMISSION_RECEIPT_PREDECESSOR_MISMATCH")
        _current_admission(self.identity, _decode(row["candidate"]), receipt, pointer,
                           _Readback(pub["candidate_id"], row["candidate"], pub["pointer"]))
        return AdmissionSnapshot(pub["publication_id"], row["candidate"], pub["pointer"],
                                 pub["receipt"], row["anchors"], row["binding"])

    def load_current(self) -> AdmissionSnapshot | None:
        if self._phase is not None or self._suspended:
            raise DurableAdmissionError("ADMISSION_ACTIVE_OR_SUSPENDED_READ_DENIED")
        try:
            if self._file_identity != _direct_file(self.path):
                raise DurableAdmissionError("ADMISSION_DB_IDENTITY_CHANGED")
            self._con.execute("BEGIN")
            _schema(self._con)
            result = self._snapshot()
            self._con.execute("COMMIT")
            return result
        except Exception:
            if self._con.in_transaction:
                self._con.execute("ROLLBACK")
            raise DurableAdmissionError("ADMISSION_CURRENT_READ_FAILED") from None

    def read_current_memory_binding_bytes(self) -> bytes | None:
        """Project persisted bindings from one verified read-only CURRENT snapshot.

        No intent or caller-supplied row ID is accepted. load_current() validates
        schema, saved hashes, the actual Memory row, R3 receipt and pointer first.
        This adds no SQL schema, writes, issuer, or fresh authorization.
        """
        snapshot = self.load_current()
        if snapshot is None:
            return None
        binding = snapshot.binding
        return _canonical({
            "schema": MEMORY_BINDING_SCHEMA,
            "pointer_sha256": _hash(snapshot.pointer_bytes),
            "candidate_sha256": _hash(snapshot.candidate_bytes),
            "memory_id": binding["memory_id"], "namespace": binding["namespace"],
            "person_record_id": binding["candidate_id"], "source_record_id": binding["source_record_id"],
        })

    def read_current_pointer_bytes(self) -> bytes | None:
        if self._phase == "PROMOTING" and self._con.in_transaction:
            row = self._current_row()
            return None if row is None else row["pointer"]
        # R3 callback reads and ordinary R4 reads use actual SQLite, not a cached ALLOW.
        if self._phase is not None:
            result = self._snapshot()
            if self._phase == "INITIAL":
                self._expected_publication = None if result is None else result.publication_id
            return None if result is None else result.pointer_bytes
        result = self.load_current()
        return None if result is None else result.pointer_bytes

    def _check_expected(self) -> None:
        row = self._current_row()
        actual = None if row is None else row["publication_id"]
        if actual != self._expected_publication:
            raise AdmissionStoreConflict("ADMISSION_CURRENT_GENERATION_CONFLICT")

    def commit_candidate_not_current(self, candidate_id: str, candidate_bytes: bytes) -> None:
        if self.read_only or self._phase != "CANDIDATE" or self._active is None:
            raise DurableAdmissionError("ADMISSION_DIRECT_WRITE_DENIED")
        active = self._active
        if candidate_id != active["record"]["id"] or candidate_bytes != _canonical(active["record"]):
            raise DurableAdmissionError("ADMISSION_CANDIDATE_INPUT_MISMATCH")
        assert_current_effect_allowed("person.admission.candidate_write")
        _schema(self._con)
        self._con.execute("BEGIN IMMEDIATE")
        try:
            self._check_expected()
            self._verify_binding(active["at"])
            existing = self._candidate_row(candidate_id)
            anchors, binding = _canonical(active["anchors"]), _canonical(active["binding"])
            expected = (self.twin_key, candidate_id, candidate_bytes, _hash(candidate_bytes),
                        anchors, _hash(anchors), binding, _hash(binding))
            if existing is None:
                self._con.execute("INSERT INTO person_admission_candidates VALUES(?,?,?,?,?,?,?,?)", expected)
            elif tuple(existing) != expected:
                raise AdmissionStoreConflict("ADMISSION_CANDIDATE_REBIND_DENIED")
            assert_current_effect_allowed("person.admission.candidate_commit")
            _schema(self._con)
            self._candidate_commit_state = "UNKNOWN"
            self._con.execute("COMMIT")
            self._candidate_commit_state = "CONFIRMED"
            self._candidate_committed = True
        except Exception:
            if self._con.in_transaction:
                self._con.execute("ROLLBACK")
            raise

    def promote_current_pointer(self, *, expected_pointer_sha256: str | None, pointer_bytes: bytes) -> None:
        if self.read_only or self._phase != "PROMOTING" or not self._con.in_transaction or self._next_publication is None:
            raise DurableAdmissionError("ADMISSION_DIRECT_PROMOTION_DENIED")
        assert_current_effect_allowed("person.admission.pointer_write")
        self._check_expected()
        row = self._current_row()
        actual_hash = None if row is None else _hash(row["pointer"])
        if actual_hash != expected_pointer_sha256:
            raise AdmissionStoreConflict("ADMISSION_POINTER_HASH_CONFLICT")
        _decode(pointer_bytes)
        # Deferred FK makes COMMIT of this pointer without its real R3 receipt fail.
        self._con.execute("INSERT INTO person_admission_current VALUES(?,?,?,?) ON CONFLICT(twin_key) DO UPDATE SET publication_id=excluded.publication_id,pointer=excluded.pointer,pointer_hash=excluded.pointer_hash",
                          (self.twin_key, self._next_publication, pointer_bytes, _hash(pointer_bytes)))

    def _verify_binding(self, at: str) -> None:
        active = self._active
        if active is None or self._row_binding(active["record"], active["anchors"],
                                               active["binding"]["memory_id"], active["binding"]["namespace"], at=at) != active["binding"]:
            raise DurableAdmissionError("ADMISSION_MEMORY_BINDING_CHANGED")

    def _fresh(self, reader: Callable[[], Mapping[str, Any]]) -> dict[str, Any]:
        value = _decode(_canonical(dict(reader())))
        if set(value) != {"current_revocation_ledger", "at"} or not isinstance(value["at"], str):
            raise DurableAdmissionError("ADMISSION_FRESH_INPUT_INVALID")
        self._active["at"] = value["at"]
        return value

    def _result(self, status: str, reason: str, snapshot: AdmissionSnapshot | None = None) -> dict[str, Any]:
        if self._candidate_commit_state == "UNKNOWN":
            status, reason = "HOLD", "CANDIDATE_COMMIT_OUTCOME_UNKNOWN"
        return dict(schema=SCHEMA, status=status, reason=reason,
                    candidate_persisted=(None if self._candidate_commit_state == "UNKNOWN" else self._candidate_committed),
                    candidate_commit_state=self._candidate_commit_state,
                    commit_state=self._commit_state,
                    possible_persisted_effect=self._candidate_commit_state != "NOT_ATTEMPTED" or self._commit_state != "NOT_ATTEMPTED",
                    attempt_publication_id=self._next_publication,
                    publication_id=(self._next_publication if self._commit_state == "CONFIRMED" else None),
                    admission_receipt=None if snapshot is None else snapshot.receipt,
                    **_CEILING)

    def admit(self, *, consent_receipt: Mapping[str, Any], source_record: Mapping[str, Any],
              candidate_record: Mapping[str, Any], purpose: str, memory_id: int, namespace: str,
              read_current_evidence: Callable[[], Mapping[str, Any]]) -> dict[str, Any]:
        """Bounded owner-invoked composition; no fresh authority is loaded from SQL.

        Candidate staging commits separately. CURRENT pointer + the actual final
        R3 receipt + exact row binding become visible in one promotion transaction.
        Any uncertain commit or failed postcommit readback is HOLD, never retried.
        """
        if self.read_only or self._phase is not None or self._suspended:
            raise DurableAdmissionError("ADMISSION_WRITE_MODE_OR_REENTRY_DENIED")
        self._candidate_committed, self._commit_state = False, "NOT_ATTEMPTED"
        self._candidate_commit_state = "NOT_ATTEMPTED"
        result = None
        self._next_publication = None
        try:
            assert_current_effect_allowed("person.admission.admit")
            if self._file_identity != _direct_file(self.path):
                raise DurableAdmissionError("ADMISSION_DB_IDENTITY_CHANGED")
            _schema(self._con)
            record = _decode(_canonical(dict(candidate_record)))
            anchors = _decode(_canonical(dict(identity=self.identity, consent_receipt=dict(consent_receipt),
                                               source_record=dict(source_record), purpose=purpose)))
            validate_person_twin_record(record, identity=self.identity,
                                       consent_receipt=anchors["consent_receipt"], source_record=anchors["source_record"])
            binding = self._row_binding(record, anchors, memory_id, namespace)
            self._active = dict(record=record, anchors=anchors, binding=binding, at=None)
            self._phase = "INITIAL"
            coordinator = PersonTwinAdmissionCoordinator(self, session_id=record["admission_session_id"],
                identity=self.identity, consent_receipt=anchors["consent_receipt"],
                source_record=anchors["source_record"], candidate_record=record, purpose=purpose)
            for phase, method, expected in (
                ("VALIDATE", coordinator.validate, "VALIDATED"),
                ("CANDIDATE", coordinator.commit_not_current, "COMMITTED_NOT_CURRENT"),
                ("POSTVERIFY", coordinator.postverify, "POSTVERIFY_PASS"),
            ):
                self._phase = phase
                evidence = self._fresh(read_current_evidence)
                ledger_key = "revocation_ledger" if phase == "VALIDATE" else "current_revocation_ledger"
                receipt = method(**{ledger_key: evidence["current_revocation_ledger"]}, at=evidence["at"])
                if receipt["state"] != expected:
                    result = self._result("HOLD", "R3_" + phase + "_HELD")
                    return result
            assert_current_effect_allowed("person.admission.promotion_begin")
            _schema(self._con)
            self._con.execute("BEGIN IMMEDIATE")
            self._phase = "PROMOTING"
            self._check_expected()
            self._next_publication = uuid.uuid4().hex
            evidence = self._fresh(read_current_evidence)
            self._verify_binding(evidence["at"])
            receipt = coordinator.promote_current(**evidence)
            if receipt["state"] != "CURRENT":
                raise DurableAdmissionError("ADMISSION_R3_PROMOTION_HELD")
            row = self._current_row()
            receipt_bytes = _canonical(receipt)
            self._con.execute("INSERT INTO person_admission_publications VALUES(?,?,?,?,?,?,?,?,?)",
                (self._next_publication, self.twin_key, record["id"], row["pointer"], row["pointer_hash"],
                 receipt_bytes, _hash(receipt_bytes), _hash(_canonical(binding)), self._expected_publication))
            before_commit = self._snapshot()
            if before_commit is None or before_commit.receipt_bytes != receipt_bytes:
                raise DurableAdmissionError("ADMISSION_TRANSACTION_READBACK_FAILED")
            assert_current_effect_allowed("person.admission.promotion_commit")
            _schema(self._con)
            self._commit_state = "UNKNOWN"
            self._con.execute("COMMIT")
            self._commit_state = "CONFIRMED"
            self._phase = None
            with PersonTwinAdmissionStore(self.path, identity=self.identity, timeout=self.timeout) as fresh:
                if fresh._file_identity != self._file_identity:
                    raise DurableAdmissionError("ADMISSION_POSTCOMMIT_FILE_CHANGED")
                verified = fresh.load_current()
            if verified != before_commit:
                raise DurableAdmissionError("ADMISSION_POSTCOMMIT_SNAPSHOT_CHANGED")
            result = self._result("PASS", "CURRENT_COMMITTED_AND_FRESH_READBACK_VERIFIED", verified)
            return result
        except Exception:
            reason = ("COMMIT_OUTCOME_UNKNOWN" if self._commit_state == "UNKNOWN" else
                      "POSTCOMMIT_READBACK_FAILED" if self._commit_state == "CONFIRMED" else
                      "ADMISSION_FAILED_CLOSED")
            result = self._result("HOLD", reason)
            return result
        finally:
            try:
                if self._con.in_transaction:
                    self._con.execute("ROLLBACK")
            except Exception:
                self._suspended = True
                if result is not None:
                    result.update(status="HOLD", reason="ROLLBACK_UNVERIFIED",
                                  possible_persisted_effect=True, admission_receipt=None)
                try:
                    self._con.close()
                except Exception:
                    pass
            finally:
                self._phase, self._active = None, None
