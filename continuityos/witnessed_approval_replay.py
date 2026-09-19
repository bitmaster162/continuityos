"""Witnessed multi-host replay with rollback/tamper detection and recovery.

R24 composes PostgreSQL replay state with an external append-only witness.  The
witness is authoritative for monotonic claim history; PostgreSQL can be rebuilt
from witnessed records after a database snapshot rollback.  R25 adds bounded
retry hardening for PostgreSQL serialization/deadlock aborts discovered by the
real qualification harness.  No witness backend is silently substituted or
auto-provisioned.
"""
from __future__ import annotations

import importlib
import json
from typing import Any, Callable, Mapping

from .multi_host_approval_replay import (
    ALREADY_CONSUMED,
    BACKEND,
    CLAIMED,
    CONFLICT,
    MULTI_HOST,
    SCHEMA as R23_SCHEMA,
    MultiHostApprovalReplayError,
    _approval_id,
    _canonical_json,
    _close_quietly,
    _dsn,
    _hex64,
    _namespace,
    _receipt,
    _sha256_text,
)

SCHEMA = "continuityos.witnessed_approval_replay/v1"
STATE_SCHEMA = "continuityos.replay_witness_state/v1"
RECORD_SCHEMA = "continuityos.replay_witness_record/v1"
ROLLBACK_PROTECTION = "EXTERNAL_APPEND_ONLY_WITNESS"
WITNESS_SCOPE = "EXTERNAL_APPEND_ONLY"
GENESIS_DOMAIN = "continuityos.replay_witness_genesis/v1"
_RETRYABLE_TRANSACTION_SQLSTATES = frozenset({"40001", "40P01"})


def _is_retryable_transaction_error(exc: BaseException) -> bool:
    current: BaseException | None = exc
    seen: set[int] = set()
    for _depth in range(8):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        sqlstate = getattr(current, "sqlstate", None)
        if sqlstate is None:
            sqlstate = getattr(current, "pgcode", None)
        if sqlstate in _RETRYABLE_TRANSACTION_SQLSTATES:
            return True
        current = current.__cause__ or current.__context__
    return False


def _generation(value: object) -> int:
    if type(value) is not int or value < 0:
        raise MultiHostApprovalReplayError("witnessed replay: invalid generation")
    return value


def _genesis_head(namespace: str) -> str:
    return _sha256_text(_canonical_json({
        "schema": GENESIS_DOMAIN,
        "namespace": namespace,
    }))


def _state(namespace: str, generation: int, head_sha256: str) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "namespace": namespace,
        "generation": _generation(generation),
        "head_sha256": _hex64("head_sha256", head_sha256),
    }


def _require_state(value: Any, *, namespace: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "schema", "namespace", "generation", "head_sha256"
    }:
        raise MultiHostApprovalReplayError("witnessed replay: witness state invalid")
    if value["schema"] != STATE_SCHEMA or value["namespace"] != namespace:
        raise MultiHostApprovalReplayError("witnessed replay: witness state invalid")
    return _state(namespace, value["generation"], value["head_sha256"])


def _record_core(
    *,
    namespace: str,
    generation: int,
    previous_head_sha256: str,
    approval_id: str,
    subject: dict[str, Any],
    subject_sha256: str,
    nonce: str,
    digest_sha256: str,
) -> dict[str, Any]:
    return {
        "schema": RECORD_SCHEMA,
        "namespace": namespace,
        "generation": _generation(generation),
        "previous_head_sha256": _hex64(
            "previous_head_sha256", previous_head_sha256
        ),
        "approval_id": _approval_id(approval_id),
        "subject": dict(subject),
        "subject_sha256": _hex64("subject_sha256", subject_sha256),
        "nonce": _hex64("nonce", nonce),
        "digest_sha256": _hex64("digest_sha256", digest_sha256),
    }


def _build_record(
    *,
    namespace: str,
    generation: int,
    previous_head_sha256: str,
    approval_id: str,
    subject: dict[str, Any],
    nonce: str,
    digest_sha256: str,
) -> dict[str, Any]:
    subject_json = _canonical_json(subject)
    core = _record_core(
        namespace=namespace,
        generation=generation,
        previous_head_sha256=previous_head_sha256,
        approval_id=approval_id,
        subject=dict(subject),
        subject_sha256=_sha256_text(subject_json),
        nonce=nonce,
        digest_sha256=digest_sha256,
    )
    head = _sha256_text(_canonical_json(core))
    return {**core, "head_sha256": head, "record_id": "rwr_" + head}


def _require_record(
    value: Any,
    *,
    namespace: str,
    expected_generation: int | None = None,
    expected_previous_head: str | None = None,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "schema", "namespace", "generation", "previous_head_sha256",
        "approval_id", "subject", "subject_sha256", "nonce",
        "digest_sha256", "head_sha256", "record_id",
    }:
        raise MultiHostApprovalReplayError("witnessed replay: witness record invalid")
    if value["schema"] != RECORD_SCHEMA or value["namespace"] != namespace:
        raise MultiHostApprovalReplayError("witnessed replay: witness record invalid")
    if type(value["subject"]) is not dict:
        raise MultiHostApprovalReplayError("witnessed replay: witness record invalid")
    rebuilt = _build_record(
        namespace=namespace,
        generation=value["generation"],
        previous_head_sha256=value["previous_head_sha256"],
        approval_id=value["approval_id"],
        subject=dict(value["subject"]),
        nonce=value["nonce"],
        digest_sha256=value["digest_sha256"],
    )
    if rebuilt != value:
        raise MultiHostApprovalReplayError("witnessed replay: witness record tampered")
    if expected_generation is not None and value["generation"] != expected_generation:
        raise MultiHostApprovalReplayError("witnessed replay: witness generation gap")
    if (
        expected_previous_head is not None
        and value["previous_head_sha256"] != expected_previous_head
    ):
        raise MultiHostApprovalReplayError("witnessed replay: witness chain mismatch")
    return dict(value)


class PostgresWitnessedApprovalReplayAuthority:
    """R24 PostgreSQL replay authority backed by an external monotonic witness."""

    replay_scope = MULTI_HOST
    backend = BACKEND
    rollback_protection = ROLLBACK_PROTECTION

    def __init__(
        self,
        dsn: str,
        *,
        witness: Any,
        namespace: str = "human-approval",
        connect: Callable[[str], Any] | None = None,
    ) -> None:
        self.dsn = _dsn(dsn)
        self.namespace = _namespace(namespace)
        if getattr(witness, "witness_scope", None) != WITNESS_SCOPE:
            raise MultiHostApprovalReplayError(
                "witnessed replay: external append-only witness required"
            )
        for name in ("current_state", "records_after", "append_record"):
            if not callable(getattr(witness, name, None)):
                raise MultiHostApprovalReplayError(
                    "witnessed replay: witness contract invalid"
                )
        self.witness = witness
        if connect is None:
            try:
                module = importlib.import_module("psycopg")
                connect = module.connect
            except (ImportError, AttributeError) as exc:
                raise MultiHostApprovalReplayError(
                    "witnessed replay: psycopg backend unavailable"
                ) from exc
        self._connect = connect
        self._initialize()
        self.synchronize()

    def _open(self) -> Any:
        try:
            return self._connect(self.dsn)
        except Exception as exc:
            raise MultiHostApprovalReplayError(
                "witnessed replay: PostgreSQL connection failed"
            ) from exc

    def _initialize(self) -> None:
        con = self._open()
        cur = None
        try:
            cur = con.cursor()
            cur.execute(
                "CREATE TABLE IF NOT EXISTS continuityos_replay_meta ("
                "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS continuityos_approval_claims ("
                "namespace TEXT NOT NULL, approval_id TEXT NOT NULL, "
                "subject_json TEXT NOT NULL, subject_sha256 TEXT NOT NULL, "
                "nonce TEXT NOT NULL, digest_sha256 TEXT NOT NULL, "
                "PRIMARY KEY(namespace, approval_id))"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS continuityos_replay_witness_state ("
                "namespace TEXT PRIMARY KEY, generation BIGINT NOT NULL, "
                "head_sha256 TEXT NOT NULL)"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS continuityos_replay_witness_journal ("
                "namespace TEXT NOT NULL, generation BIGINT NOT NULL, "
                "previous_head_sha256 TEXT NOT NULL, head_sha256 TEXT NOT NULL, "
                "approval_id TEXT NOT NULL, subject_json TEXT NOT NULL, "
                "subject_sha256 TEXT NOT NULL, nonce TEXT NOT NULL, "
                "digest_sha256 TEXT NOT NULL, "
                "PRIMARY KEY(namespace, generation), "
                "UNIQUE(namespace, approval_id))"
            )
            cur.execute(
                "INSERT INTO continuityos_replay_meta(key, value) "
                "VALUES('schema', %s) ON CONFLICT (key) DO NOTHING",
                (R23_SCHEMA,),
            )
            cur.execute(
                "INSERT INTO continuityos_replay_meta(key, value) "
                "VALUES('witness_schema', %s) ON CONFLICT (key) DO NOTHING",
                (SCHEMA,),
            )
            self._require_schema_meta(cur)
            cur.execute(
                "SELECT generation, head_sha256 "
                "FROM continuityos_replay_witness_state WHERE namespace=%s",
                (self.namespace,),
            )
            state_row = cur.fetchone()
            if state_row is None:
                cur.execute(
                    "SELECT COUNT(*) FROM continuityos_approval_claims "
                    "WHERE namespace=%s",
                    (self.namespace,),
                )
                count_row = cur.fetchone()
                if count_row is None or type(count_row[0]) is not int:
                    raise MultiHostApprovalReplayError(
                        "witnessed replay: claim count unavailable"
                    )
                if count_row[0] != 0:
                    raise MultiHostApprovalReplayError(
                        "witnessed replay: explicit R23 migration required"
                    )
                cur.execute(
                    "INSERT INTO continuityos_replay_witness_state("
                    "namespace, generation, head_sha256) VALUES(%s, %s, %s)",
                    (self.namespace, 0, _genesis_head(self.namespace)),
                )
            else:
                _state(self.namespace, state_row[0], state_row[1])
            con.commit()
        except MultiHostApprovalReplayError:
            try:
                con.rollback()
            except Exception:
                pass
            raise
        except Exception as exc:
            try:
                con.rollback()
            except Exception:
                pass
            raise MultiHostApprovalReplayError(
                "witnessed replay: schema initialization failed"
            ) from exc
        finally:
            _close_quietly(cur)
            _close_quietly(con)

    def _require_schema_meta(self, cur: Any) -> None:
        cur.execute(
            "SELECT value FROM continuityos_replay_meta WHERE key='schema'"
        )
        if cur.fetchone() != (R23_SCHEMA,):
            raise MultiHostApprovalReplayError(
                "witnessed replay: R23 schema identity mismatch"
            )
        cur.execute(
            "SELECT value FROM continuityos_replay_meta WHERE key='witness_schema'"
        )
        if cur.fetchone() != (SCHEMA,):
            raise MultiHostApprovalReplayError(
                "witnessed replay: R24 schema identity mismatch"
            )

    def _witness_current(self) -> dict[str, Any]:
        try:
            value = self.witness.current_state(self.namespace)
        except Exception as exc:
            raise MultiHostApprovalReplayError(
                "witnessed replay: witness unavailable"
            ) from exc
        return _require_state(value, namespace=self.namespace)

    def _witness_records_after(self, generation: int) -> list[dict[str, Any]]:
        try:
            value = self.witness.records_after(self.namespace, generation)
        except Exception as exc:
            raise MultiHostApprovalReplayError(
                "witnessed replay: witness history unavailable"
            ) from exc
        if type(value) is not list:
            raise MultiHostApprovalReplayError(
                "witnessed replay: witness history invalid"
            )
        return [dict(item) if type(item) is dict else item for item in value]

    def _append_witness(
        self,
        *,
        expected_generation: int,
        expected_head_sha256: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            value = self.witness.append_record(
                self.namespace,
                expected_generation,
                expected_head_sha256,
                dict(record),
            )
        except Exception as exc:
            raise MultiHostApprovalReplayError(
                "witnessed replay: witness append failed"
            ) from exc
        observed = _require_record(
            value,
            namespace=self.namespace,
            expected_generation=record["generation"],
            expected_previous_head=record["previous_head_sha256"],
        )
        if observed != record:
            raise MultiHostApprovalReplayError(
                "witnessed replay: witness append readback mismatch"
            )
        return observed

    def _read_state_for_update(self, cur: Any) -> dict[str, Any]:
        cur.execute(
            "SELECT generation, head_sha256 "
            "FROM continuityos_replay_witness_state "
            "WHERE namespace=%s FOR UPDATE",
            (self.namespace,),
        )
        row = cur.fetchone()
        if row is None:
            raise MultiHostApprovalReplayError(
                "witnessed replay: database state missing"
            )
        return _state(self.namespace, row[0], row[1])

    def _audit_database(
        self, cur: Any, state_value: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        generation = _generation(state_value["generation"])
        expected_head = _genesis_head(self.namespace)
        cur.execute(
            "SELECT generation, previous_head_sha256, head_sha256, approval_id, "
            "subject_json, subject_sha256, nonce, digest_sha256 "
            "FROM continuityos_replay_witness_journal "
            "WHERE namespace=%s ORDER BY generation",
            (self.namespace,),
        )
        rows = list(cur.fetchall())
        if len(rows) != generation:
            raise MultiHostApprovalReplayError(
                "witnessed replay: database journal length mismatch"
            )
        records: list[dict[str, Any]] = []
        journal_claims: dict[str, tuple[str, str, str, str]] = {}
        for index, row in enumerate(rows, start=1):
            (
                row_generation, previous_head, row_head, approval_id,
                subject_json, subject_sha, nonce, digest,
            ) = row
            if row_generation != index or previous_head != expected_head:
                raise MultiHostApprovalReplayError(
                    "witnessed replay: database journal chain mismatch"
                )
            try:
                subject = json.loads(subject_json)
            except Exception as exc:
                raise MultiHostApprovalReplayError(
                    "witnessed replay: database journal subject invalid"
                ) from exc
            if type(subject) is not dict or _canonical_json(subject) != subject_json:
                raise MultiHostApprovalReplayError(
                    "witnessed replay: database journal subject invalid"
                )
            record = _build_record(
                namespace=self.namespace,
                generation=row_generation,
                previous_head_sha256=previous_head,
                approval_id=approval_id,
                subject=dict(subject),
                nonce=nonce,
                digest_sha256=digest,
            )
            if record["head_sha256"] != row_head or record["subject_sha256"] != subject_sha:
                raise MultiHostApprovalReplayError(
                    "witnessed replay: database journal tampered"
                )
            records.append(record)
            journal_claims[approval_id] = (
                subject_json, subject_sha, nonce, digest
            )
            expected_head = row_head
        if expected_head != state_value["head_sha256"]:
            raise MultiHostApprovalReplayError(
                "witnessed replay: database state head mismatch"
            )
        cur.execute(
            "SELECT approval_id, subject_json, subject_sha256, nonce, digest_sha256 "
            "FROM continuityos_approval_claims WHERE namespace=%s ORDER BY approval_id",
            (self.namespace,),
        )
        claim_rows = list(cur.fetchall())
        claims = {
            row[0]: (row[1], row[2], row[3], row[4]) for row in claim_rows
        }
        if len(claim_rows) != generation or claims != journal_claims:
            raise MultiHostApprovalReplayError(
                "witnessed replay: database claim set tampered"
            )
        return records

    def _apply_record(self, cur: Any, record: Mapping[str, Any]) -> None:
        subject_json = _canonical_json(record["subject"])
        expected_claim = (
            subject_json,
            record["subject_sha256"],
            record["nonce"],
            record["digest_sha256"],
        )
        cur.execute(
            "INSERT INTO continuityos_approval_claims("
            "namespace, approval_id, subject_json, subject_sha256, nonce, digest_sha256"
            ") VALUES(%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (namespace, approval_id) DO NOTHING "
            "RETURNING subject_json, subject_sha256, nonce, digest_sha256",
            (
                self.namespace,
                record["approval_id"],
                *expected_claim,
            ),
        )
        inserted = cur.fetchone()
        if inserted is None:
            cur.execute(
                "SELECT subject_json, subject_sha256, nonce, digest_sha256 "
                "FROM continuityos_approval_claims "
                "WHERE namespace=%s AND approval_id=%s",
                (self.namespace, record["approval_id"]),
            )
            inserted = cur.fetchone()
        if inserted is None or tuple(inserted) != expected_claim:
            raise MultiHostApprovalReplayError(
                "witnessed replay: recovery claim conflict"
            )
        expected_journal = (
            record["previous_head_sha256"],
            record["head_sha256"],
            record["approval_id"],
            subject_json,
            record["subject_sha256"],
            record["nonce"],
            record["digest_sha256"],
        )
        cur.execute(
            "INSERT INTO continuityos_replay_witness_journal("
            "namespace, generation, previous_head_sha256, head_sha256, approval_id, "
            "subject_json, subject_sha256, nonce, digest_sha256"
            ") VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (namespace, generation) DO NOTHING "
            "RETURNING previous_head_sha256, head_sha256, approval_id, "
            "subject_json, subject_sha256, nonce, digest_sha256",
            (
                self.namespace,
                record["generation"],
                *expected_journal,
            ),
        )
        journal_row = cur.fetchone()
        if journal_row is None:
            cur.execute(
                "SELECT previous_head_sha256, head_sha256, approval_id, "
                "subject_json, subject_sha256, nonce, digest_sha256 "
                "FROM continuityos_replay_witness_journal "
                "WHERE namespace=%s AND generation=%s",
                (self.namespace, record["generation"]),
            )
            journal_row = cur.fetchone()
        if journal_row is None or tuple(journal_row) != expected_journal:
            raise MultiHostApprovalReplayError(
                "witnessed replay: recovery journal conflict"
            )
        cur.execute(
            "UPDATE continuityos_replay_witness_state "
            "SET generation=%s, head_sha256=%s "
            "WHERE namespace=%s AND generation=%s AND head_sha256=%s "
            "RETURNING generation, head_sha256",
            (
                record["generation"],
                record["head_sha256"],
                self.namespace,
                record["generation"] - 1,
                record["previous_head_sha256"],
            ),
        )
        if cur.fetchone() != (record["generation"], record["head_sha256"]):
            raise MultiHostApprovalReplayError(
                "witnessed replay: database state CAS failed"
            )

    def _snapshot_database(self) -> dict[str, Any]:
        for _attempt in range(8):
            con = self._open()
            cur = None
            try:
                cur = con.cursor()
                cur.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                self._require_schema_meta(cur)
                value = self._read_state_for_update(cur)
                self._audit_database(cur, value)
                con.commit()
                return dict(value)
            except MultiHostApprovalReplayError:
                try:
                    con.rollback()
                except Exception:
                    pass
                raise
            except Exception as exc:
                try:
                    con.rollback()
                except Exception:
                    pass
                if _is_retryable_transaction_error(exc):
                    continue
                raise MultiHostApprovalReplayError(
                    "witnessed replay: database snapshot failed"
                ) from exc
            finally:
                _close_quietly(cur)
                _close_quietly(con)
        raise MultiHostApprovalReplayError(
            "witnessed replay: database snapshot contention"
        )

    def _read_claim_row(
        self, approval_id: str
    ) -> tuple[str, str, str, str] | None:
        for _attempt in range(8):
            con = self._open()
            cur = None
            try:
                cur = con.cursor()
                cur.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                self._require_schema_meta(cur)
                cur.execute(
                    "SELECT subject_json, subject_sha256, nonce, digest_sha256 "
                    "FROM continuityos_approval_claims "
                    "WHERE namespace=%s AND approval_id=%s",
                    (self.namespace, approval_id),
                )
                row = cur.fetchone()
                con.commit()
                return None if row is None else tuple(row)
            except MultiHostApprovalReplayError:
                try:
                    con.rollback()
                except Exception:
                    pass
                raise
            except Exception as exc:
                try:
                    con.rollback()
                except Exception:
                    pass
                if _is_retryable_transaction_error(exc):
                    continue
                raise MultiHostApprovalReplayError(
                    "witnessed replay: claim read failed"
                ) from exc
            finally:
                _close_quietly(cur)
                _close_quietly(con)
        raise MultiHostApprovalReplayError(
            "witnessed replay: claim read contention"
        )

    def _receipt_for_existing(
        self,
        *,
        approval_id: str,
        subject: dict[str, Any],
        subject_sha256: str,
        nonce: str,
        digest_sha256: str,
        existing: tuple[str, str, str, str],
    ) -> dict[str, Any]:
        same = existing == (
            _canonical_json(subject), subject_sha256, nonce, digest_sha256
        )
        return _receipt(
            namespace=self.namespace,
            approval_id=approval_id,
            subject=dict(subject),
            subject_sha256=subject_sha256,
            nonce=nonce,
            digest_sha256=digest_sha256,
            status=ALREADY_CONSUMED if same else CONFLICT,
            existing=(existing[1], existing[2], existing[3]),
        )

    def synchronize(self) -> dict[str, Any]:
        for _attempt in range(8):
            db_snapshot = self._snapshot_database()

            # External witness I/O is deliberately outside every PostgreSQL
            # transaction/row lock. The witness CAS is the global monotonic
            # serializer; PostgreSQL is revalidated before applying its prefix.
            witness_state = self._witness_current()
            if witness_state["generation"] < db_snapshot["generation"]:
                raise MultiHostApprovalReplayError(
                    "witnessed replay: database ahead of witness"
                )

            needed = witness_state["generation"] - db_snapshot["generation"]
            history: list[dict[str, Any]] = []
            if needed:
                observed_history = self._witness_records_after(
                    db_snapshot["generation"]
                )
                if len(observed_history) < needed:
                    raise MultiHostApprovalReplayError(
                        "witnessed replay: witness history incomplete"
                    )
                history = observed_history[:needed]

            con = self._open()
            cur = None
            try:
                cur = con.cursor()
                cur.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                self._require_schema_meta(cur)
                locked_state = self._read_state_for_update(cur)
                self._audit_database(cur, locked_state)
                if locked_state != db_snapshot:
                    con.rollback()
                    continue

                if witness_state["generation"] == locked_state["generation"]:
                    if witness_state["head_sha256"] != locked_state["head_sha256"]:
                        raise MultiHostApprovalReplayError(
                            "witnessed replay: database/witness head mismatch"
                        )
                    con.commit()
                    return dict(locked_state)

                expected_generation = locked_state["generation"]
                expected_head = locked_state["head_sha256"]
                for raw in history:
                    record = _require_record(
                        raw,
                        namespace=self.namespace,
                        expected_generation=expected_generation + 1,
                        expected_previous_head=expected_head,
                    )
                    self._apply_record(cur, record)
                    expected_generation = record["generation"]
                    expected_head = record["head_sha256"]

                if (
                    expected_generation != witness_state["generation"]
                    or expected_head != witness_state["head_sha256"]
                ):
                    raise MultiHostApprovalReplayError(
                        "witnessed replay: witness history incomplete"
                    )
                recovered = _state(
                    self.namespace, expected_generation, expected_head
                )
                self._audit_database(cur, recovered)
                con.commit()
                return recovered
            except MultiHostApprovalReplayError:
                try:
                    con.rollback()
                except Exception:
                    pass
                raise
            except Exception as exc:
                try:
                    con.rollback()
                except Exception:
                    pass
                if _is_retryable_transaction_error(exc):
                    continue
                raise MultiHostApprovalReplayError(
                    "witnessed replay: synchronization failed"
                ) from exc
            finally:
                _close_quietly(cur)
                _close_quietly(con)

        raise MultiHostApprovalReplayError(
            "witnessed replay: database synchronization contention"
        )

    def claim_once(
        self,
        *,
        approval_id: str,
        subject: dict[str, Any],
        nonce: str,
        digest_sha256: str,
    ) -> dict[str, Any]:
        identifier = _approval_id(approval_id)
        subject_value = dict(subject)
        subject_json = _canonical_json(subject_value)
        subject_sha256 = _sha256_text(subject_json)
        nonce_value = _hex64("nonce", nonce)
        digest_value = _hex64("digest_sha256", digest_sha256)

        last_append_error: MultiHostApprovalReplayError | None = None
        for _attempt in range(8):
            state_value = self.synchronize()
            existing = self._read_claim_row(identifier)
            if existing is not None:
                return self._receipt_for_existing(
                    approval_id=identifier,
                    subject=subject_value,
                    subject_sha256=subject_sha256,
                    nonce=nonce_value,
                    digest_sha256=digest_value,
                    existing=existing,
                )

            record = _build_record(
                namespace=self.namespace,
                generation=state_value["generation"] + 1,
                previous_head_sha256=state_value["head_sha256"],
                approval_id=identifier,
                subject=subject_value,
                nonce=nonce_value,
                digest_sha256=digest_value,
            )

            try:
                self._append_witness(
                    expected_generation=state_value["generation"],
                    expected_head_sha256=state_value["head_sha256"],
                    record=record,
                )
            except MultiHostApprovalReplayError as exc:
                last_append_error = exc
                # CAS loss to another writer is recoverable. An ambiguous
                # append outcome is never promoted to CLAIMED: after recovery
                # an exact row is ALREADY_CONSUMED, preserving one-success.
                try:
                    self.synchronize()
                    existing = self._read_claim_row(identifier)
                except MultiHostApprovalReplayError:
                    raise exc
                if existing is not None:
                    return self._receipt_for_existing(
                        approval_id=identifier,
                        subject=subject_value,
                        subject_sha256=subject_sha256,
                        nonce=nonce_value,
                        digest_sha256=digest_value,
                        existing=existing,
                    )
                continue

            # The append succeeded outside the DB critical section. Reconcile
            # the authoritative witness prefix, then prove our exact row exists.
            self.synchronize()
            existing = self._read_claim_row(identifier)
            expected = (subject_json, subject_sha256, nonce_value, digest_value)
            if existing != expected:
                raise MultiHostApprovalReplayError(
                    "witnessed replay: appended claim recovery mismatch"
                )
            return _receipt(
                namespace=self.namespace,
                approval_id=identifier,
                subject=subject_value,
                subject_sha256=subject_sha256,
                nonce=nonce_value,
                digest_sha256=digest_value,
                status=CLAIMED,
            )

        if last_append_error is not None:
            raise last_append_error
        raise MultiHostApprovalReplayError(
            "witnessed replay: claim contention exceeded"
        )


__all__ = [
    "SCHEMA",
    "STATE_SCHEMA",
    "RECORD_SCHEMA",
    "ROLLBACK_PROTECTION",
    "WITNESS_SCOPE",
    "PostgresWitnessedApprovalReplayAuthority",
]
