"""Common Operational Memory v1 — shadow-only, append-only operational state.

This module is deliberately narrower than the general-purpose ``Memory`` facade.
It provides a deterministic local SQLite substrate for:

* append-only operational events with a SHA-256 hash chain;
* bi-temporal claims with explicit evidence state and supersession;
* bounded decisions with human/controller authority requirements;
* immutable evidence references;
* broker-custody import that preserves ``UNREVIEWED`` / ``NOT_APPLIED`` ceilings;
* checkpoints and deterministic replay projections.

It does **not** own accepted Control Center truth, apply state deltas, deploy,
trade, or grant capital permission.  Version 1 is shadow-only.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

SCHEMA_VERSION = 1
SCHEMA_NAME = "continuityos.common_operational_memory.v1"
DEFAULT_FILENAME = "common_operational_memory_v1.db"
ZERO_HASH = "0" * 64

EVIDENCE_STATES = {
    "VERIFIED",
    "SOURCE_BACKED",
    "INFERENCE",
    "ASSUMPTION",
    "HYPOTHESIS",
    "UNKNOWN",
}
DECISION_STATES = {"PROPOSED", "ACCEPTED", "REJECTED", "HOLD", "SUPERSEDED"}
AUTHORITY_CLASSES = {"AGENT", "HUMAN", "DETERMINISTIC_CONTROLLER"}
PHYSICAL_STATUSES = {
    "REPORTED",
    "LOCATED",
    "HASH_VERIFIED",
    "PHYSICALLY_ACCEPTED",
    "QUARANTINED",
    "REJECTED",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DRIVE_MARKERS = (
    "\\my drive\\",
    "/my drive/",
    "\\google drive\\",
    "/google drive/",
    "\\drivefs\\",
    "/drivefs/",
    "\\onedrive\\",
    "/onedrive/",
    "\\00_return_drop\\",
    "/00_return_drop/",
)


class OperationalMemoryError(RuntimeError):
    """Base exception for Common Operational Memory."""


class IdentityConflict(OperationalMemoryError):
    """An existing immutable identity was reused with different content."""


class PolicyViolation(OperationalMemoryError):
    """A request violates a normative v1 safety boundary."""


class IntegrityFailure(OperationalMemoryError):
    """Stored data failed deterministic integrity verification."""


def _format_utc(value: _dt.datetime) -> str:
    return value.astimezone(_dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _utc_now() -> str:
    return _format_utc(_dt.datetime.now(_dt.timezone.utc))


def _normalize_time(value: Optional[str], *, field: str) -> str:
    if value is None:
        return _utc_now()
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty ISO-8601 string")
    raw = value.strip()
    parse = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        parsed = _dt.datetime.fromisoformat(parse)
    except ValueError as exc:
        raise ValueError(f"{field} is not ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return _format_utc(parsed)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _strict_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    obj: Dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def strict_json_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_strict_object, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {value}")))


def strict_json_load(path: os.PathLike[str] | str) -> Any:
    return strict_json_loads(Path(path).read_text(encoding="utf-8-sig"))


def default_operational_db() -> str:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            base = str(Path.home() / "AppData" / "Local")
        return str(Path(base) / "ContinuityOS" / DEFAULT_FILENAME)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "state"
    return str(base / "continuityos" / DEFAULT_FILENAME)


def resolve_operational_db(path: Optional[str] = None) -> str:
    raw = path or os.environ.get("CONTINUITYOS_OPERATIONAL_DB") or default_operational_db()
    if raw == ":memory:":
        return raw
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("operational memory database path is empty")
    if raw.startswith("\\\\") or raw.startswith("//"):
        raise PolicyViolation("operational memory database must be on a local filesystem")
    expanded = os.path.expandvars(os.path.expanduser(raw.strip()))
    normalized = os.path.realpath(os.path.abspath(expanded))
    probe = (normalized.replace("/", os.sep).replace("\\", os.sep) + os.sep).casefold()
    probe_slash = probe.replace(os.sep, "/")
    if any(marker.casefold() in probe or marker.casefold() in probe_slash for marker in _DRIVE_MARKERS):
        raise PolicyViolation("operational memory database must not be stored in DriveFS or a synced return-drop path")
    return os.path.normcase(normalized)


def _validate_sha256(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value.lower()):
        raise ValueError(f"{field} must be a lowercase 64-character SHA-256 hex string")
    return value.lower()


def normalize_evidence_refs(refs: Optional[Sequence[Mapping[str, Any]]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for idx, ref in enumerate(refs or []):
        if not isinstance(ref, Mapping):
            raise ValueError(f"evidence_refs[{idx}] must be an object")
        allowed = {"sha256", "locator", "kind", "scope"}
        extra = set(ref) - allowed
        if extra:
            raise ValueError(f"evidence_refs[{idx}] has unsupported keys: {sorted(extra)}")
        sha = _validate_sha256(str(ref.get("sha256", "")), field=f"evidence_refs[{idx}].sha256")
        locator = ref.get("locator")
        if not isinstance(locator, str) or not locator.strip():
            raise ValueError(f"evidence_refs[{idx}].locator must be non-empty")
        item = {"sha256": sha, "locator": locator.strip()}
        if ref.get("kind") is not None:
            if not isinstance(ref["kind"], str) or not ref["kind"].strip():
                raise ValueError(f"evidence_refs[{idx}].kind must be non-empty")
            item["kind"] = ref["kind"].strip()
        if ref.get("scope") is not None:
            if not isinstance(ref["scope"], str) or not ref["scope"].strip():
                raise ValueError(f"evidence_refs[{idx}].scope must be non-empty")
            item["scope"] = ref["scope"].strip()
        out.append(item)
    out.sort(key=lambda item: (item["sha256"], item["locator"], item.get("kind", ""), item.get("scope", "")))
    return out


def _nonempty(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _normalize_physical_status(value: Any) -> str:
    """Normalize broker status without promoting unknown text to verified custody."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return "REPORTED"
    raw = str(value).strip().upper()
    aliases = {
        "PASS": "HASH_VERIFIED",
        "VERIFIED": "HASH_VERIFIED",
        "HASH_MATCH": "HASH_VERIFIED",
        "CRC_PASS": "HASH_VERIFIED",
        "READY": "HASH_VERIFIED",
        "READY_FOR_BROKER_PUBLICATION": "HASH_VERIFIED",
        "PHYSICAL_ACCEPTANCE_PASS": "PHYSICALLY_ACCEPTED",
        "ACCEPTED": "PHYSICALLY_ACCEPTED",
        "DELIVERY_VERIFIED": "PHYSICALLY_ACCEPTED",
    }
    normalized = aliases.get(raw, raw)
    if normalized in PHYSICAL_STATUSES:
        return normalized
    # Fail downward. Unknown prose is a report, never verification evidence.
    return "REPORTED"


def _safe_registry_snapshot(raw: Mapping[str, Any], normalized: Mapping[str, Any]) -> Dict[str, Any]:
    """Keep only normalized custody facts and source key names, never arbitrary values."""
    return {
        "normalized": dict(normalized),
        "source_keys": sorted(str(key) for key in raw.keys()),
    }


def _event_core(
    *,
    stream: str,
    event_type: str,
    subject_id: str,
    actor_type: str,
    actor_id: str,
    occurred_at: str,
    payload: Any,
    evidence_refs: Sequence[Mapping[str, Any]],
    source_event_id: Optional[str],
) -> Dict[str, Any]:
    return {
        "stream": stream,
        "event_type": event_type,
        "subject_id": subject_id,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "occurred_at": occurred_at,
        "payload": payload,
        "evidence_refs": list(evidence_refs),
        "source_event_id": source_event_id,
    }


@dataclass(frozen=True)
class AppendResult:
    identity: str
    sequence: int
    inserted: bool
    content_hash: str
    chain_hash: str


class OperationalMemory:
    """Append-only shadow operational memory backed by local SQLite WAL."""

    def __init__(
        self,
        path: Optional[str] = None,
        *,
        read_only: bool = False,
        immutable: bool = False,
    ):
        self.path = resolve_operational_db(path)
        self.read_only = bool(read_only)
        self.immutable = bool(immutable)
        if self.immutable and not self.read_only:
            raise ValueError("immutable operational memory requires read_only=True")
        if self.immutable and self.path != ":memory:":
            wal = Path(self.path + "-wal")
            if wal.exists() and wal.stat().st_size > 0:
                raise PolicyViolation("immutable read requires a quiescent database with no pending WAL frames")
        self._lock = threading.RLock()
        if self.path == ":memory:":
            if read_only:
                raise ValueError("read-only operational memory requires a file")
            self.con = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        elif read_only:
            if not os.path.isfile(self.path):
                raise FileNotFoundError(self.path)
            query = "?mode=ro&immutable=1" if self.immutable else "?mode=ro"
            uri = Path(self.path).as_uri() + query
            self.con = sqlite3.connect(uri, uri=True, check_same_thread=False, isolation_level=None)
        else:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self.con = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA foreign_keys=ON")
        self.con.execute("PRAGMA busy_timeout=5000")
        if self.read_only:
            self.con.execute("PRAGMA query_only=ON")
        if not read_only:
            mode = self.con.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal" and self.path != ":memory:":
                raise OperationalMemoryError(f"SQLite WAL unavailable for local operational DB: {mode}")
            self.con.execute("PRAGMA synchronous=FULL")
            self.con.execute("PRAGMA wal_autocheckpoint=1000")
            self._init_schema()
        else:
            self._assert_schema()

    def close(self) -> None:
        self.con.close()

    def __enter__(self) -> "OperationalMemory":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @contextlib.contextmanager
    def _write_tx(self) -> Iterator[sqlite3.Connection]:
        if self.read_only:
            raise PolicyViolation("operational memory is opened read-only")
        with self._lock:
            self.con.execute("BEGIN IMMEDIATE")
            try:
                yield self.con
            except Exception:
                self.con.rollback()
                raise
            else:
                self.con.commit()

    def _init_schema(self) -> None:
        with self._write_tx() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    stream TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    source_event_id TEXT,
                    content_hash TEXT NOT NULL,
                    prev_chain_hash TEXT NOT NULL,
                    chain_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS idx_events_stream_sequence ON events(stream, sequence);
                CREATE INDEX IF NOT EXISTS idx_events_subject_sequence ON events(subject_id, sequence);
                CREATE INDEX IF NOT EXISTS idx_events_type_sequence ON events(event_type, sequence);

                CREATE TABLE IF NOT EXISTS claims(
                    claim_id TEXT PRIMARY KEY,
                    subject_id TEXT NOT NULL,
                    predicate TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    evidence_state TEXT NOT NULL,
                    valid_from TEXT NOT NULL,
                    valid_to TEXT,
                    recorded_at TEXT NOT NULL,
                    supersedes_id TEXT,
                    source_event_id TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    claim_hash TEXT NOT NULL UNIQUE,
                    FOREIGN KEY(supersedes_id) REFERENCES claims(claim_id),
                    FOREIGN KEY(source_event_id) REFERENCES events(event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_claims_key ON claims(subject_id, predicate, scope, recorded_at);
                CREATE INDEX IF NOT EXISTS idx_claims_supersedes ON claims(supersedes_id);

                CREATE TABLE IF NOT EXISTS decisions(
                    decision_id TEXT PRIMARY KEY,
                    subject_id TEXT NOT NULL,
                    decision_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    authority_class TEXT NOT NULL,
                    authority_id TEXT NOT NULL,
                    authority_ref TEXT,
                    recorded_at TEXT NOT NULL,
                    supersedes_id TEXT,
                    source_event_id TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    decision_hash TEXT NOT NULL UNIQUE,
                    FOREIGN KEY(supersedes_id) REFERENCES decisions(decision_id),
                    FOREIGN KEY(source_event_id) REFERENCES events(event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_decisions_subject ON decisions(subject_id, decision_type, recorded_at);
                CREATE INDEX IF NOT EXISTS idx_decisions_supersedes ON decisions(supersedes_id);

                CREATE TABLE IF NOT EXISTS broker_custody(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    delivery_id TEXT NOT NULL UNIQUE,
                    zip_sha256 TEXT NOT NULL,
                    generation TEXT,
                    slot TEXT,
                    work_order_id TEXT,
                    physical_status TEXT NOT NULL,
                    content_status TEXT NOT NULL CHECK(content_status='UNREVIEWED'),
                    apply_status TEXT NOT NULL CHECK(apply_status='NOT_APPLIED'),
                    source_registry_sha256 TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    identity_hash TEXT NOT NULL UNIQUE,
                    record_hash TEXT NOT NULL UNIQUE,
                    source_event_id TEXT NOT NULL,
                    FOREIGN KEY(source_event_id) REFERENCES events(event_id),
                    UNIQUE(delivery_id, zip_sha256)
                );
                CREATE INDEX IF NOT EXISTS idx_broker_slot ON broker_custody(generation, slot, sequence);

                CREATE TABLE IF NOT EXISTS checkpoints(
                    checkpoint_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL,
                    projection_sha256 TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    checkpoint_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS idx_checkpoints_sequence ON checkpoints(event_sequence, recorded_at);

                CREATE TRIGGER IF NOT EXISTS deny_events_update
                BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS deny_events_delete
                BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS deny_claims_update
                BEFORE UPDATE ON claims BEGIN SELECT RAISE(ABORT, 'claims are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS deny_claims_delete
                BEFORE DELETE ON claims BEGIN SELECT RAISE(ABORT, 'claims are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS deny_decisions_update
                BEFORE UPDATE ON decisions BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS deny_decisions_delete
                BEFORE DELETE ON decisions BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS deny_broker_custody_update
                BEFORE UPDATE ON broker_custody BEGIN SELECT RAISE(ABORT, 'broker custody is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS deny_broker_custody_delete
                BEFORE DELETE ON broker_custody BEGIN SELECT RAISE(ABORT, 'broker custody is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS deny_checkpoints_update
                BEFORE UPDATE ON checkpoints BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS deny_checkpoints_delete
                BEFORE DELETE ON checkpoints BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only'); END;
                """
            )
            existing = con.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
            if existing is None:
                con.execute("INSERT INTO schema_meta(key,value) VALUES('schema_name',?)", (SCHEMA_NAME,))
                con.execute("INSERT INTO schema_meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
                con.execute("INSERT INTO schema_meta(key,value) VALUES('mode','SHADOW_ONLY')")
                con.execute("INSERT INTO schema_meta(key,value) VALUES('can_trade','false')")
                con.execute("INSERT INTO schema_meta(key,value) VALUES('capital_permission','DENY')")
                con.execute("INSERT INTO schema_meta(key,value) VALUES('deploy_permission','DENY')")
                con.execute("INSERT INTO schema_meta(key,value) VALUES('self_application','false')")
                con.execute("INSERT INTO schema_meta(key,value) VALUES('apply_enabled','false')")
            elif int(existing[0]) != SCHEMA_VERSION:
                raise OperationalMemoryError(
                    f"unsupported operational memory schema version {existing[0]} (expected {SCHEMA_VERSION})"
                )

    def _assert_schema(self) -> None:
        row = self.con.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        if row is None or int(row[0]) != SCHEMA_VERSION:
            raise OperationalMemoryError("not a Common Operational Memory v1 database")

    def metadata(self) -> Dict[str, str]:
        return {row["key"]: row["value"] for row in self.con.execute("SELECT key,value FROM schema_meta ORDER BY key")}

    def _append_event_tx(
        self,
        con: sqlite3.Connection,
        *,
        stream: str,
        event_type: str,
        subject_id: str,
        actor_type: str,
        actor_id: str,
        payload: Any,
        evidence_refs: Optional[Sequence[Mapping[str, Any]]] = None,
        occurred_at: Optional[str] = None,
        recorded_at: Optional[str] = None,
        source_event_id: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> AppendResult:
        stream = _nonempty(stream, field="stream")
        event_type = _nonempty(event_type, field="event_type")
        subject_id = _nonempty(subject_id, field="subject_id")
        actor_type = _nonempty(actor_type, field="actor_type").upper()
        actor_id = _nonempty(actor_id, field="actor_id")
        if actor_type not in AUTHORITY_CLASSES:
            raise ValueError(f"actor_type must be one of {sorted(AUTHORITY_CLASSES)}")
        occurred = _normalize_time(occurred_at, field="occurred_at")
        recorded = _normalize_time(recorded_at, field="recorded_at")
        refs = normalize_evidence_refs(evidence_refs)
        core = _event_core(
            stream=stream,
            event_type=event_type,
            subject_id=subject_id,
            actor_type=actor_type,
            actor_id=actor_id,
            occurred_at=occurred,
            payload=payload,
            evidence_refs=refs,
            source_event_id=source_event_id,
        )
        content_hash = _sha256_text(_canonical_json(core))
        eid = event_id or f"evt-{content_hash[:32]}"
        eid = _nonempty(eid, field="event_id")
        existing = con.execute(
            "SELECT sequence,content_hash,chain_hash FROM events WHERE event_id=?", (eid,)
        ).fetchone()
        if existing is not None:
            if existing["content_hash"] != content_hash:
                raise IdentityConflict(f"event_id {eid} already exists with different content")
            return AppendResult(eid, int(existing["sequence"]), False, content_hash, existing["chain_hash"])
        prev = con.execute("SELECT chain_hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        prev_hash = prev[0] if prev else ZERO_HASH
        chain_body = {
            "event_id": eid,
            "content_hash": content_hash,
            "prev_chain_hash": prev_hash,
            "recorded_at": recorded,
        }
        chain_hash = _sha256_text(_canonical_json(chain_body))
        cur = con.execute(
            """
            INSERT INTO events(
                event_id,stream,event_type,subject_id,actor_type,actor_id,
                occurred_at,recorded_at,payload_json,evidence_refs_json,
                source_event_id,content_hash,prev_chain_hash,chain_hash
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                eid,
                stream,
                event_type,
                subject_id,
                actor_type,
                actor_id,
                occurred,
                recorded,
                _canonical_json(payload),
                _canonical_json(refs),
                source_event_id,
                content_hash,
                prev_hash,
                chain_hash,
            ),
        )
        return AppendResult(eid, int(cur.lastrowid), True, content_hash, chain_hash)

    def append_event(self, **kwargs: Any) -> AppendResult:
        with self._write_tx() as con:
            return self._append_event_tx(con, **kwargs)

    def record_claim(
        self,
        *,
        subject_id: str,
        predicate: str,
        value: Any,
        scope: str = "global",
        evidence_state: str,
        evidence_refs: Optional[Sequence[Mapping[str, Any]]] = None,
        valid_from: Optional[str] = None,
        valid_to: Optional[str] = None,
        supersedes_id: Optional[str] = None,
        actor_type: str = "AGENT",
        actor_id: str = "unknown",
        claim_id: Optional[str] = None,
        recorded_at: Optional[str] = None,
    ) -> AppendResult:
        subject_id = _nonempty(subject_id, field="subject_id")
        predicate = _nonempty(predicate, field="predicate")
        scope = _nonempty(scope, field="scope")
        state = _nonempty(evidence_state, field="evidence_state").upper()
        if state not in EVIDENCE_STATES:
            raise ValueError(f"evidence_state must be one of {sorted(EVIDENCE_STATES)}")
        refs = normalize_evidence_refs(evidence_refs)
        if state != "UNKNOWN" and not refs:
            raise PolicyViolation(f"{state} claim requires at least one immutable evidence reference")
        vf = _normalize_time(valid_from, field="valid_from")
        vt = _normalize_time(valid_to, field="valid_to") if valid_to is not None else None
        if vt is not None and vt <= vf:
            raise ValueError("valid_to must be later than valid_from")
        rec = _normalize_time(recorded_at, field="recorded_at")
        core = {
            "subject_id": subject_id,
            "predicate": predicate,
            "value": value,
            "scope": scope,
            "evidence_state": state,
            "valid_from": vf,
            "valid_to": vt,
            "recorded_at": rec,
            "supersedes_id": supersedes_id,
            "evidence_refs": refs,
        }
        claim_hash = _sha256_text(_canonical_json(core))
        cid = claim_id or f"clm-{claim_hash[:32]}"
        with self._write_tx() as con:
            existing = con.execute("SELECT claim_hash,source_event_id FROM claims WHERE claim_id=?", (cid,)).fetchone()
            if existing is not None:
                if existing["claim_hash"] != claim_hash:
                    raise IdentityConflict(f"claim_id {cid} already exists with different content")
                event = con.execute(
                    "SELECT sequence,content_hash,chain_hash FROM events WHERE event_id=?",
                    (existing["source_event_id"],),
                ).fetchone()
                return AppendResult(existing["source_event_id"], int(event["sequence"]), False, event["content_hash"], event["chain_hash"])
            if supersedes_id is not None:
                old = con.execute(
                    "SELECT subject_id,predicate,scope FROM claims WHERE claim_id=?", (supersedes_id,)
                ).fetchone()
                if old is None:
                    raise ValueError(f"supersedes claim not found: {supersedes_id}")
                if (old["subject_id"], old["predicate"], old["scope"]) != (subject_id, predicate, scope):
                    raise PolicyViolation("a claim may supersede only the same subject/predicate/scope")
                already = con.execute("SELECT claim_id FROM claims WHERE supersedes_id=?", (supersedes_id,)).fetchone()
                if already is not None:
                    raise PolicyViolation(f"claim {supersedes_id} is already superseded by {already['claim_id']}")
            event = self._append_event_tx(
                con,
                stream="operational.claims",
                event_type="CLAIM_RECORDED",
                subject_id=subject_id,
                actor_type=actor_type,
                actor_id=actor_id,
                payload={"claim_id": cid, "claim_hash": claim_hash, "predicate": predicate, "scope": scope},
                evidence_refs=refs,
                occurred_at=vf,
                recorded_at=rec,
            )
            con.execute(
                """
                INSERT INTO claims(
                    claim_id,subject_id,predicate,value_json,scope,evidence_state,
                    valid_from,valid_to,recorded_at,supersedes_id,source_event_id,
                    evidence_refs_json,claim_hash
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    cid,
                    subject_id,
                    predicate,
                    _canonical_json(value),
                    scope,
                    state,
                    vf,
                    vt,
                    rec,
                    supersedes_id,
                    event.identity,
                    _canonical_json(refs),
                    claim_hash,
                ),
            )
            return event

    def record_decision(
        self,
        *,
        subject_id: str,
        decision_type: str,
        state: str,
        value: Any,
        rationale: str,
        authority_class: str,
        authority_id: str,
        authority_ref: Optional[str] = None,
        evidence_refs: Optional[Sequence[Mapping[str, Any]]] = None,
        supersedes_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        recorded_at: Optional[str] = None,
    ) -> AppendResult:
        subject_id = _nonempty(subject_id, field="subject_id")
        decision_type = _nonempty(decision_type, field="decision_type")
        state = _nonempty(state, field="state").upper()
        if state not in DECISION_STATES:
            raise ValueError(f"state must be one of {sorted(DECISION_STATES)}")
        authority_class = _nonempty(authority_class, field="authority_class").upper()
        if authority_class not in AUTHORITY_CLASSES:
            raise ValueError(f"authority_class must be one of {sorted(AUTHORITY_CLASSES)}")
        authority_id = _nonempty(authority_id, field="authority_id")
        rationale = _nonempty(rationale, field="rationale")
        refs = normalize_evidence_refs(evidence_refs)
        if state in {"ACCEPTED", "REJECTED", "HOLD", "SUPERSEDED"}:
            if authority_class not in {"HUMAN", "DETERMINISTIC_CONTROLLER"}:
                raise PolicyViolation(f"{state} decisions require HUMAN or DETERMINISTIC_CONTROLLER authority")
            if not isinstance(authority_ref, str) or not authority_ref.strip():
                raise PolicyViolation(f"{state} decisions require an authority_ref")
            if not refs:
                raise PolicyViolation(f"{state} decisions require immutable evidence_refs")
        rec = _normalize_time(recorded_at, field="recorded_at")
        core = {
            "subject_id": subject_id,
            "decision_type": decision_type,
            "state": state,
            "value": value,
            "rationale": rationale,
            "authority_class": authority_class,
            "authority_id": authority_id,
            "authority_ref": authority_ref,
            "recorded_at": rec,
            "supersedes_id": supersedes_id,
            "evidence_refs": refs,
        }
        decision_hash = _sha256_text(_canonical_json(core))
        did = decision_id or f"dec-{decision_hash[:32]}"
        with self._write_tx() as con:
            existing = con.execute(
                "SELECT decision_hash,source_event_id FROM decisions WHERE decision_id=?", (did,)
            ).fetchone()
            if existing is not None:
                if existing["decision_hash"] != decision_hash:
                    raise IdentityConflict(f"decision_id {did} already exists with different content")
                event = con.execute(
                    "SELECT sequence,content_hash,chain_hash FROM events WHERE event_id=?",
                    (existing["source_event_id"],),
                ).fetchone()
                return AppendResult(existing["source_event_id"], int(event["sequence"]), False, event["content_hash"], event["chain_hash"])
            if supersedes_id is not None:
                old = con.execute(
                    "SELECT subject_id,decision_type FROM decisions WHERE decision_id=?", (supersedes_id,)
                ).fetchone()
                if old is None:
                    raise ValueError(f"supersedes decision not found: {supersedes_id}")
                if (old["subject_id"], old["decision_type"]) != (subject_id, decision_type):
                    raise PolicyViolation("a decision may supersede only the same subject/decision_type")
                already = con.execute(
                    "SELECT decision_id FROM decisions WHERE supersedes_id=?", (supersedes_id,)
                ).fetchone()
                if already is not None:
                    raise PolicyViolation(
                        f"decision {supersedes_id} is already superseded by {already['decision_id']}"
                    )
            event = self._append_event_tx(
                con,
                stream="operational.decisions",
                event_type="DECISION_RECORDED",
                subject_id=subject_id,
                actor_type=authority_class,
                actor_id=authority_id,
                payload={
                    "decision_id": did,
                    "decision_hash": decision_hash,
                    "decision_type": decision_type,
                    "state": state,
                    "authority_ref": authority_ref,
                },
                evidence_refs=refs,
                occurred_at=rec,
                recorded_at=rec,
            )
            con.execute(
                """
                INSERT INTO decisions(
                    decision_id,subject_id,decision_type,state,value_json,rationale,
                    authority_class,authority_id,authority_ref,recorded_at,
                    supersedes_id,source_event_id,evidence_refs_json,decision_hash
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    did,
                    subject_id,
                    decision_type,
                    state,
                    _canonical_json(value),
                    rationale,
                    authority_class,
                    authority_id,
                    authority_ref.strip() if isinstance(authority_ref, str) else None,
                    rec,
                    supersedes_id,
                    event.identity,
                    _canonical_json(refs),
                    decision_hash,
                ),
            )
            return event

    @staticmethod
    def _registry_rows(path: Path) -> Tuple[List[Dict[str, Any]], str]:
        raw = path.read_bytes()
        source_sha = hashlib.sha256(raw).hexdigest()
        rows: List[Dict[str, Any]] = []
        if path.suffix.lower() == ".jsonl":
            for lineno, line in enumerate(raw.decode("utf-8-sig").splitlines(), 1):
                if not line.strip():
                    continue
                value = strict_json_loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"registry line {lineno} is not an object")
                rows.append(value)
        else:
            value = strict_json_loads(raw.decode("utf-8-sig"))
            if isinstance(value, list):
                rows = value
            elif isinstance(value, dict) and isinstance(value.get("rows"), list):
                rows = value["rows"]
            elif isinstance(value, dict) and isinstance(value.get("deliveries"), list):
                rows = value["deliveries"]
            else:
                raise ValueError("registry JSON must be a list or contain rows/deliveries")
            if not all(isinstance(row, dict) for row in rows):
                raise ValueError("registry contains a non-object row")
        return rows, source_sha

    @staticmethod
    def _extract_delivery(row: Mapping[str, Any]) -> Dict[str, Any]:
        delivery_id = row.get("delivery_id") or row.get("id")
        zip_sha = row.get("zip_sha256") or row.get("sha256") or row.get("artifact_sha256")
        if isinstance(row.get("zip"), Mapping):
            delivery_id = delivery_id or row["zip"].get("delivery_id")
            zip_sha = zip_sha or row["zip"].get("sha256")
        delivery_id = _nonempty(delivery_id, field="delivery_id")
        zip_sha = _validate_sha256(str(zip_sha or "").lower(), field="zip_sha256")
        physical = _normalize_physical_status(
            row.get("physical_status")
            or row.get("verification_status")
            or row.get("status")
        )
        return {
            "delivery_id": delivery_id,
            "zip_sha256": zip_sha,
            "generation": row.get("generation"),
            "slot": row.get("slot") or row.get("actor") or row.get("role"),
            "work_order_id": row.get("work_order_id"),
            "physical_status": physical,
        }

    def import_broker_registry(
        self,
        registry_path: os.PathLike[str] | str,
        *,
        actor_id: str = "broker-import",
    ) -> Dict[str, Any]:
        path = Path(registry_path).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        rows, source_sha = self._registry_rows(path)
        normalized = [self._extract_delivery(row) for row in rows]
        if len({item["delivery_id"] for item in normalized}) != len(normalized):
            raise IdentityConflict("source registry contains duplicate delivery_id values")
        inserted = 0
        duplicates = 0
        with self._write_tx() as con:
            for raw, item in zip(rows, normalized):
                existing = con.execute(
                    "SELECT zip_sha256,source_event_id FROM broker_custody WHERE delivery_id=?",
                    (item["delivery_id"],),
                ).fetchone()
                if existing is not None:
                    if existing["zip_sha256"] != item["zip_sha256"]:
                        raise IdentityConflict(
                            f"delivery_id {item['delivery_id']} already bound to another ZIP hash"
                        )
                    duplicates += 1
                    continue
                identity_hash = _sha256_text(
                    _canonical_json(
                        {"delivery_id": item["delivery_id"], "zip_sha256": item["zip_sha256"]}
                    )
                )
                record_core = {
                    **item,
                    "content_status": "UNREVIEWED",
                    "apply_status": "NOT_APPLIED",
                    "source_registry_sha256": source_sha,
                }
                record_hash = _sha256_text(_canonical_json(record_core))
                refs = [
                    {
                        "sha256": source_sha,
                        "locator": str(path),
                        "kind": "BROKER_REGISTRY",
                    },
                    {
                        "sha256": item["zip_sha256"],
                        "locator": f"broker://delivery/{item['delivery_id']}",
                        "kind": "STRICT_RETURN_ZIP",
                    },
                ]
                event = self._append_event_tx(
                    con,
                    stream="operational.broker_custody",
                    event_type="BROKER_CUSTODY_IMPORTED",
                    subject_id=item["delivery_id"],
                    actor_type="DETERMINISTIC_CONTROLLER",
                    actor_id=actor_id,
                    payload={
                        **item,
                        "content_status": "UNREVIEWED",
                        "apply_status": "NOT_APPLIED",
                    },
                    evidence_refs=refs,
                    source_event_id=None,
                )
                con.execute(
                    """
                    INSERT INTO broker_custody(
                        delivery_id,zip_sha256,generation,slot,work_order_id,
                        physical_status,content_status,apply_status,
                        source_registry_sha256,imported_at,raw_json,identity_hash,record_hash,source_event_id
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        item["delivery_id"],
                        item["zip_sha256"],
                        item["generation"],
                        item["slot"],
                        item["work_order_id"],
                        item["physical_status"],
                        "UNREVIEWED",
                        "NOT_APPLIED",
                        source_sha,
                        _utc_now(),
                        _canonical_json(_safe_registry_snapshot(raw, item)),
                        identity_hash,
                        record_hash,
                        event.identity,
                    ),
                )
                inserted += 1
        return {
            "schema": "continuityos.common_operational_memory.broker_import.v1",
            "source": str(path),
            "source_sha256": source_sha,
            "rows": len(rows),
            "inserted": inserted,
            "duplicates": duplicates,
            "content_status": "UNREVIEWED",
            "apply_status": "NOT_APPLIED",
            "can_trade": False,
            "capital_permission": "DENY",
        }

    def _sequence_for_event(self, event_id: str) -> int:
        row = self.con.execute("SELECT sequence FROM events WHERE event_id=?", (event_id,)).fetchone()
        if row is None:
            raise IntegrityFailure(f"referenced event does not exist: {event_id}")
        return int(row[0])

    def projection(
        self,
        *,
        event_sequence: Optional[int] = None,
        valid_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        max_row = self.con.execute("SELECT COALESCE(MAX(sequence),0) FROM events").fetchone()
        max_sequence = int(max_row[0])
        cursor = max_sequence if event_sequence is None else int(event_sequence)
        if cursor < 0 or cursor > max_sequence:
            raise ValueError(f"event_sequence must be between 0 and {max_sequence}")
        event_ids = {
            row["event_id"]
            for row in self.con.execute("SELECT event_id FROM events WHERE sequence<=?", (cursor,))
        }
        valid_row = self.con.execute(
            "SELECT MAX(occurred_at) FROM events WHERE sequence<=?", (cursor,)
        ).fetchone()
        derived_valid_at = valid_row[0] if valid_row and valid_row[0] is not None else None
        selected_valid_at = (
            _normalize_time(valid_at, field="valid_at") if valid_at is not None else derived_valid_at
        )
        claim_rows = [
            row for row in self.con.execute("SELECT * FROM claims ORDER BY recorded_at,claim_id")
            if row["source_event_id"] in event_ids
            and (
                selected_valid_at is None
                or (
                    row["valid_from"] <= selected_valid_at
                    and (row["valid_to"] is None or selected_valid_at < row["valid_to"])
                )
            )
        ]
        superseded_claims = {
            row["supersedes_id"] for row in claim_rows if row["supersedes_id"] is not None
        }
        current_claims = []
        for row in claim_rows:
            if row["claim_id"] in superseded_claims:
                continue
            current_claims.append(
                {
                    "claim_id": row["claim_id"],
                    "subject_id": row["subject_id"],
                    "predicate": row["predicate"],
                    "value": strict_json_loads(row["value_json"]),
                    "scope": row["scope"],
                    "evidence_state": row["evidence_state"],
                    "valid_from": row["valid_from"],
                    "valid_to": row["valid_to"],
                    "recorded_at": row["recorded_at"],
                    "supersedes_id": row["supersedes_id"],
                    "source_event_id": row["source_event_id"],
                    "evidence_refs": strict_json_loads(row["evidence_refs_json"]),
                    "claim_hash": row["claim_hash"],
                }
            )
        decision_rows = [
            row for row in self.con.execute("SELECT * FROM decisions ORDER BY recorded_at,decision_id")
            if row["source_event_id"] in event_ids
        ]
        superseded_decisions = {
            row["supersedes_id"] for row in decision_rows if row["supersedes_id"] is not None
        }
        current_decisions = []
        for row in decision_rows:
            if row["decision_id"] in superseded_decisions:
                continue
            current_decisions.append(
                {
                    "decision_id": row["decision_id"],
                    "subject_id": row["subject_id"],
                    "decision_type": row["decision_type"],
                    "state": row["state"],
                    "value": strict_json_loads(row["value_json"]),
                    "rationale": row["rationale"],
                    "authority_class": row["authority_class"],
                    "authority_id": row["authority_id"],
                    "authority_ref": row["authority_ref"],
                    "recorded_at": row["recorded_at"],
                    "supersedes_id": row["supersedes_id"],
                    "source_event_id": row["source_event_id"],
                    "evidence_refs": strict_json_loads(row["evidence_refs_json"]),
                    "decision_hash": row["decision_hash"],
                }
            )
        custody = []
        for row in self.con.execute("SELECT * FROM broker_custody ORDER BY delivery_id"):
            if row["source_event_id"] not in event_ids:
                continue
            custody.append(
                {
                    "delivery_id": row["delivery_id"],
                    "zip_sha256": row["zip_sha256"],
                    "generation": row["generation"],
                    "slot": row["slot"],
                    "work_order_id": row["work_order_id"],
                    "physical_status": row["physical_status"],
                    "content_status": row["content_status"],
                    "apply_status": row["apply_status"],
                    "source_registry_sha256": row["source_registry_sha256"],
                    "identity_hash": row["identity_hash"],
                    "record_hash": row["record_hash"],
                    "source_event_id": row["source_event_id"],
                }
            )
        head = self.con.execute(
            "SELECT chain_hash FROM events WHERE sequence<=? ORDER BY sequence DESC LIMIT 1",
            (cursor,),
        ).fetchone()
        body = {
            "schema": "continuityos.common_operational_memory.projection.v1",
            "mode": "SHADOW_ONLY",
            "event_cursor": cursor,
            "event_chain_head": head[0] if head else ZERO_HASH,
            "valid_at": selected_valid_at,
            "claims": sorted(current_claims, key=lambda x: (x["subject_id"], x["predicate"], x["scope"], x["claim_id"])),
            "decisions": sorted(current_decisions, key=lambda x: (x["subject_id"], x["decision_type"], x["decision_id"])),
            "broker_custody": custody,
            "ceilings": {
                "accepted_truth_owner": "CONTROL_CENTER",
                "content_acceptance": "NOT_PERFORMED",
                "state_apply": "DISABLED",
                "can_trade": False,
                "capital_permission": "DENY",
                "deploy_permission": "DENY",
                "self_application": False,
            },
        }
        return {**body, "projection_sha256": _sha256_text(_canonical_json(body))}

    def create_checkpoint(
        self,
        label: str,
        *,
        evidence_refs: Optional[Sequence[Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        checkpoint_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        label = _nonempty(label, field="label")
        refs = normalize_evidence_refs(evidence_refs)
        projection = self.projection()
        rec = _utc_now()
        core = {
            "label": label,
            "event_sequence": projection["event_cursor"],
            "projection_sha256": projection["projection_sha256"],
            "recorded_at": rec,
            "evidence_refs": refs,
            "metadata": dict(metadata or {}),
        }
        checkpoint_hash = _sha256_text(_canonical_json(core))
        cid = checkpoint_id or f"cp-{checkpoint_hash[:32]}"
        with self._write_tx() as con:
            existing = con.execute(
                "SELECT checkpoint_hash FROM checkpoints WHERE checkpoint_id=?", (cid,)
            ).fetchone()
            if existing is not None:
                if existing["checkpoint_hash"] != checkpoint_hash:
                    raise IdentityConflict(f"checkpoint_id {cid} already exists with different content")
                return {"checkpoint_id": cid, **core, "checkpoint_hash": checkpoint_hash, "inserted": False}
            con.execute(
                """
                INSERT INTO checkpoints(
                    checkpoint_id,label,event_sequence,projection_sha256,recorded_at,
                    evidence_refs_json,metadata_json,checkpoint_hash
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    cid,
                    label,
                    projection["event_cursor"],
                    projection["projection_sha256"],
                    rec,
                    _canonical_json(refs),
                    _canonical_json(dict(metadata or {})),
                    checkpoint_hash,
                ),
            )
        return {"checkpoint_id": cid, **core, "checkpoint_hash": checkpoint_hash, "inserted": True}

    def verify(self) -> Dict[str, Any]:
        errors: List[str] = []
        checks: List[Dict[str, Any]] = []

        def check(name: str, ok: bool, detail: Any) -> None:
            checks.append({"check": name, "ok": bool(ok), "detail": detail})
            if not ok:
                errors.append(f"{name}: {detail}")

        integrity = self.con.execute("PRAGMA integrity_check").fetchone()[0]
        check("sqlite_integrity", integrity == "ok", integrity)
        meta = self.metadata()
        check("schema_name", meta.get("schema_name") == SCHEMA_NAME, meta.get("schema_name"))
        check("schema_version", meta.get("schema_version") == str(SCHEMA_VERSION), meta.get("schema_version"))
        check("shadow_only", meta.get("mode") == "SHADOW_ONLY" and meta.get("apply_enabled") == "false", meta)
        check(
            "permission_ceiling",
            meta.get("can_trade") == "false"
            and meta.get("capital_permission") == "DENY"
            and meta.get("deploy_permission") == "DENY"
            and meta.get("self_application") == "false",
            meta,
        )
        expected_triggers = {
            "deny_events_update", "deny_events_delete",
            "deny_claims_update", "deny_claims_delete",
            "deny_decisions_update", "deny_decisions_delete",
            "deny_broker_custody_update", "deny_broker_custody_delete",
            "deny_checkpoints_update", "deny_checkpoints_delete",
        }
        found_triggers = {
            row[0] for row in self.con.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            )
        }
        check(
            "append_only_triggers",
            expected_triggers.issubset(found_triggers),
            {"missing": sorted(expected_triggers - found_triggers)},
        )

        prev = ZERO_HASH
        event_count = 0
        for row in self.con.execute("SELECT * FROM events ORDER BY sequence"):
            event_count += 1
            core = _event_core(
                stream=row["stream"],
                event_type=row["event_type"],
                subject_id=row["subject_id"],
                actor_type=row["actor_type"],
                actor_id=row["actor_id"],
                occurred_at=row["occurred_at"],
                payload=strict_json_loads(row["payload_json"]),
                evidence_refs=strict_json_loads(row["evidence_refs_json"]),
                source_event_id=row["source_event_id"],
            )
            content_hash = _sha256_text(_canonical_json(core))
            chain_hash = _sha256_text(
                _canonical_json(
                    {
                        "event_id": row["event_id"],
                        "content_hash": content_hash,
                        "prev_chain_hash": prev,
                        "recorded_at": row["recorded_at"],
                    }
                )
            )
            if row["content_hash"] != content_hash:
                errors.append(f"event {row['event_id']} content hash mismatch")
            if row["prev_chain_hash"] != prev:
                errors.append(f"event {row['event_id']} previous hash mismatch")
            if row["chain_hash"] != chain_hash:
                errors.append(f"event {row['event_id']} chain hash mismatch")
            prev = row["chain_hash"]
        check("event_chain", not any(err.startswith("event ") for err in errors), {"events": event_count, "head": prev})

        claim_errors = []
        for row in self.con.execute("SELECT * FROM claims ORDER BY claim_id"):
            refs = strict_json_loads(row["evidence_refs_json"])
            core = {
                "subject_id": row["subject_id"],
                "predicate": row["predicate"],
                "value": strict_json_loads(row["value_json"]),
                "scope": row["scope"],
                "evidence_state": row["evidence_state"],
                "valid_from": row["valid_from"],
                "valid_to": row["valid_to"],
                "recorded_at": row["recorded_at"],
                "supersedes_id": row["supersedes_id"],
                "evidence_refs": refs,
            }
            if _sha256_text(_canonical_json(core)) != row["claim_hash"]:
                claim_errors.append(f"claim {row['claim_id']} hash mismatch")
            if row["evidence_state"] not in EVIDENCE_STATES:
                claim_errors.append(f"claim {row['claim_id']} invalid evidence state")
            if row["evidence_state"] != "UNKNOWN" and not refs:
                claim_errors.append(f"claim {row['claim_id']} missing evidence")
            if self.con.execute("SELECT 1 FROM events WHERE event_id=?", (row["source_event_id"],)).fetchone() is None:
                claim_errors.append(f"claim {row['claim_id']} missing source event")
        errors.extend(claim_errors)
        check("claims", not claim_errors, {"rows": self.con.execute("SELECT COUNT(*) FROM claims").fetchone()[0]})

        decision_errors = []
        for row in self.con.execute("SELECT * FROM decisions ORDER BY decision_id"):
            refs = strict_json_loads(row["evidence_refs_json"])
            core = {
                "subject_id": row["subject_id"],
                "decision_type": row["decision_type"],
                "state": row["state"],
                "value": strict_json_loads(row["value_json"]),
                "rationale": row["rationale"],
                "authority_class": row["authority_class"],
                "authority_id": row["authority_id"],
                "authority_ref": row["authority_ref"],
                "recorded_at": row["recorded_at"],
                "supersedes_id": row["supersedes_id"],
                "evidence_refs": refs,
            }
            if _sha256_text(_canonical_json(core)) != row["decision_hash"]:
                decision_errors.append(f"decision {row['decision_id']} hash mismatch")
            if row["state"] in {"ACCEPTED", "REJECTED", "HOLD", "SUPERSEDED"}:
                if row["authority_class"] not in {"HUMAN", "DETERMINISTIC_CONTROLLER"}:
                    decision_errors.append(f"decision {row['decision_id']} invalid authority")
                if not row["authority_ref"] or not refs:
                    decision_errors.append(f"decision {row['decision_id']} missing authority/evidence")
        errors.extend(decision_errors)
        check("decisions", not decision_errors, {"rows": self.con.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]})

        custody_errors = []
        for row in self.con.execute("SELECT * FROM broker_custody ORDER BY sequence"):
            if row["content_status"] != "UNREVIEWED":
                custody_errors.append(f"delivery {row['delivery_id']} content ceiling violated")
            if row["apply_status"] != "NOT_APPLIED":
                custody_errors.append(f"delivery {row['delivery_id']} apply ceiling violated")
            expected_identity = _sha256_text(
                _canonical_json({"delivery_id": row["delivery_id"], "zip_sha256": row["zip_sha256"]})
            )
            if expected_identity != row["identity_hash"]:
                custody_errors.append(f"delivery {row['delivery_id']} identity hash mismatch")
            record_core = {
                "delivery_id": row["delivery_id"],
                "zip_sha256": row["zip_sha256"],
                "generation": row["generation"],
                "slot": row["slot"],
                "work_order_id": row["work_order_id"],
                "physical_status": row["physical_status"],
                "content_status": row["content_status"],
                "apply_status": row["apply_status"],
                "source_registry_sha256": row["source_registry_sha256"],
            }
            if _sha256_text(_canonical_json(record_core)) != row["record_hash"]:
                custody_errors.append(f"delivery {row['delivery_id']} record hash mismatch")
            if row["physical_status"] not in PHYSICAL_STATUSES:
                custody_errors.append(f"delivery {row['delivery_id']} invalid physical status")
            if self.con.execute(
                "SELECT 1 FROM events WHERE event_id=?", (row["source_event_id"],)
            ).fetchone() is None:
                custody_errors.append(f"delivery {row['delivery_id']} missing source event")
        errors.extend(custody_errors)
        check("broker_custody", not custody_errors, {"rows": self.con.execute("SELECT COUNT(*) FROM broker_custody").fetchone()[0]})

        checkpoint_errors = []
        for row in self.con.execute("SELECT * FROM checkpoints ORDER BY event_sequence,recorded_at"):
            projection = self.projection(event_sequence=int(row["event_sequence"]))
            if projection["projection_sha256"] != row["projection_sha256"]:
                checkpoint_errors.append(f"checkpoint {row['checkpoint_id']} projection mismatch")
            core = {
                "label": row["label"],
                "event_sequence": int(row["event_sequence"]),
                "projection_sha256": row["projection_sha256"],
                "recorded_at": row["recorded_at"],
                "evidence_refs": strict_json_loads(row["evidence_refs_json"]),
                "metadata": strict_json_loads(row["metadata_json"]),
            }
            if _sha256_text(_canonical_json(core)) != row["checkpoint_hash"]:
                checkpoint_errors.append(f"checkpoint {row['checkpoint_id']} hash mismatch")
        errors.extend(checkpoint_errors)
        check("checkpoints", not checkpoint_errors, {"rows": self.con.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]})

        projection = self.projection()
        return {
            "schema": "continuityos.common_operational_memory.verify.v1",
            "ok": not errors,
            "path": self.path,
            "checks": checks,
            "errors": errors,
            "event_count": event_count,
            "projection_sha256": projection["projection_sha256"],
            "mode": "SHADOW_ONLY",
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
        }


def _json_arg(value: str) -> Any:
    if value.startswith("@"):
        return strict_json_load(value[1:])
    return strict_json_loads(value)


def _refs_arg(values: Sequence[str]) -> List[Dict[str, Any]]:
    refs = []
    for value in values:
        if ":" not in value:
            raise ValueError("evidence ref must be SHA256:LOCATOR")
        sha, locator = value.split(":", 1)
        refs.append({"sha256": sha, "locator": locator})
    return refs


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-memory",
        description="Common Operational Memory v1 (shadow-only local SQLite)",
    )
    parser.add_argument("--db", default=None, help="local SQLite path (never DriveFS)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")
    sub.add_parser("status")
    sub.add_parser("verify")

    ev = sub.add_parser("event")
    ev.add_argument("--stream", required=True)
    ev.add_argument("--type", dest="event_type", required=True)
    ev.add_argument("--subject", required=True)
    ev.add_argument("--actor-type", default="AGENT", choices=sorted(AUTHORITY_CLASSES))
    ev.add_argument("--actor-id", required=True)
    ev.add_argument("--payload", default="{}", help="JSON or @file")
    ev.add_argument("--evidence", action="append", default=[], help="SHA256:LOCATOR")
    ev.add_argument("--occurred-at", default=None)
    ev.add_argument("--event-id", default=None)

    cl = sub.add_parser("claim")
    cl.add_argument("--subject", required=True)
    cl.add_argument("--predicate", required=True)
    cl.add_argument("--value", required=True, help="JSON or @file")
    cl.add_argument("--scope", default="global")
    cl.add_argument("--evidence-state", required=True, choices=sorted(EVIDENCE_STATES))
    cl.add_argument("--evidence", action="append", default=[], help="SHA256:LOCATOR")
    cl.add_argument("--valid-from", default=None)
    cl.add_argument("--valid-to", default=None)
    cl.add_argument("--supersedes", default=None)
    cl.add_argument("--actor-type", default="AGENT", choices=sorted(AUTHORITY_CLASSES))
    cl.add_argument("--actor-id", required=True)

    de = sub.add_parser("decision")
    de.add_argument("--subject", required=True)
    de.add_argument("--type", dest="decision_type", required=True)
    de.add_argument("--state", required=True, choices=sorted(DECISION_STATES))
    de.add_argument("--value", required=True, help="JSON or @file")
    de.add_argument("--rationale", required=True)
    de.add_argument("--authority-class", required=True, choices=sorted(AUTHORITY_CLASSES))
    de.add_argument("--authority-id", required=True)
    de.add_argument("--authority-ref", default=None)
    de.add_argument("--evidence", action="append", default=[], help="SHA256:LOCATOR")
    de.add_argument("--supersedes", default=None)

    br = sub.add_parser("import-broker")
    br.add_argument("registry")
    br.add_argument("--actor-id", default="broker-import")

    sn = sub.add_parser("snapshot")
    sn.add_argument("--cursor", type=int, default=None)
    sn.add_argument("--valid-at", default=None, help="independent valid-time axis (ISO-8601)")
    sn.add_argument("--out", default=None)

    cp = sub.add_parser("checkpoint")
    cp.add_argument("--label", required=True)
    cp.add_argument("--evidence", action="append", default=[], help="SHA256:LOCATOR")
    cp.add_argument("--metadata", default="{}", help="JSON or @file")

    args = parser.parse_args(argv)
    try:
        read_only = args.cmd in {"status", "verify", "snapshot"}
        if args.cmd == "init":
            read_only = False
        with OperationalMemory(args.db, read_only=read_only) as memory:
            if args.cmd == "init":
                out = {"status": "INITIALIZED", "path": memory.path, "metadata": memory.metadata()}
            elif args.cmd == "status":
                out = {
                    "path": memory.path,
                    "metadata": memory.metadata(),
                    "counts": {
                        "events": memory.con.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                        "claims": memory.con.execute("SELECT COUNT(*) FROM claims").fetchone()[0],
                        "decisions": memory.con.execute("SELECT COUNT(*) FROM decisions").fetchone()[0],
                        "broker_custody": memory.con.execute("SELECT COUNT(*) FROM broker_custody").fetchone()[0],
                        "checkpoints": memory.con.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0],
                    },
                }
            elif args.cmd == "verify":
                out = memory.verify()
            elif args.cmd == "event":
                out = memory.append_event(
                    stream=args.stream,
                    event_type=args.event_type,
                    subject_id=args.subject,
                    actor_type=args.actor_type,
                    actor_id=args.actor_id,
                    payload=_json_arg(args.payload),
                    evidence_refs=_refs_arg(args.evidence),
                    occurred_at=args.occurred_at,
                    event_id=args.event_id,
                ).__dict__
            elif args.cmd == "claim":
                out = memory.record_claim(
                    subject_id=args.subject,
                    predicate=args.predicate,
                    value=_json_arg(args.value),
                    scope=args.scope,
                    evidence_state=args.evidence_state,
                    evidence_refs=_refs_arg(args.evidence),
                    valid_from=args.valid_from,
                    valid_to=args.valid_to,
                    supersedes_id=args.supersedes,
                    actor_type=args.actor_type,
                    actor_id=args.actor_id,
                ).__dict__
            elif args.cmd == "decision":
                out = memory.record_decision(
                    subject_id=args.subject,
                    decision_type=args.decision_type,
                    state=args.state,
                    value=_json_arg(args.value),
                    rationale=args.rationale,
                    authority_class=args.authority_class,
                    authority_id=args.authority_id,
                    authority_ref=args.authority_ref,
                    evidence_refs=_refs_arg(args.evidence),
                    supersedes_id=args.supersedes,
                ).__dict__
            elif args.cmd == "import-broker":
                out = memory.import_broker_registry(args.registry, actor_id=args.actor_id)
            elif args.cmd == "snapshot":
                out = memory.projection(event_sequence=args.cursor, valid_at=args.valid_at)
                if args.out:
                    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            elif args.cmd == "checkpoint":
                out = memory.create_checkpoint(
                    args.label,
                    evidence_refs=_refs_arg(args.evidence),
                    metadata=_json_arg(args.metadata),
                )
            else:  # pragma: no cover
                raise AssertionError(args.cmd)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0 if not isinstance(out, dict) or out.get("ok", True) else 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "continuityos.common_operational_memory.error.v1",
                    "error": type(exc).__name__,
                    "message": str(exc),
                    "can_trade": False,
                    "capital_permission": "DENY",
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
