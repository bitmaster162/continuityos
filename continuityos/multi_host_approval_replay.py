"""Multi-host durable replay authority for authenticated Human approvals.

R23 adds an explicit PostgreSQL compare-and-set backend.  The authority is
shared-database based, fail-closed, and never falls back to SQLite or memory.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import re
from typing import Any, Callable, Final, Mapping

SCHEMA = "continuityos.multi_host_approval_replay/v1"
CLAIM_SCHEMA = "continuityos.multi_host_replay_claim/v1"
MULTI_HOST = "MULTI_HOST"
BACKEND = "POSTGRESQL"
CLAIMED = "CLAIMED"
ALREADY_CONSUMED = "ALREADY_CONSUMED"
CONFLICT = "CONFLICT"

_APPROVAL_ID_RE: Final = re.compile(r"^hap_[0-9a-f]{64}$")
_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_NAMESPACE_RE: Final = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,95}$")


class MultiHostApprovalReplayError(RuntimeError):
    """Raised when shared replay state cannot be trusted or updated safely."""


def _canonical_json(value: Mapping[str, Any]) -> str:
    if type(value) is not dict:
        raise ValueError("multi-host replay: subject must be dict")
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("multi-host replay: subject is not canonical JSON") from exc


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _approval_id(value: object) -> str:
    if type(value) is not str or _APPROVAL_ID_RE.fullmatch(value) is None:
        raise ValueError("multi-host replay: invalid approval_id")
    return value


def _hex64(label: str, value: object) -> str:
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        raise ValueError(f"multi-host replay: invalid {label}")
    return value


def _namespace(value: object) -> str:
    if type(value) is not str or _NAMESPACE_RE.fullmatch(value) is None:
        raise ValueError("multi-host replay: invalid namespace")
    return value


def _dsn(value: object) -> str:
    if type(value) is not str or not value:
        raise ValueError("multi-host replay: PostgreSQL DSN required")
    lowered = value.lower()
    if not (lowered.startswith("postgresql://") or lowered.startswith("postgres://")):
        raise ValueError("multi-host replay: PostgreSQL DSN required")
    return value


def _close_quietly(value: Any) -> None:
    if value is not None:
        try:
            value.close()
        except Exception:
            pass


def _receipt(
    *,
    namespace: str,
    approval_id: str,
    subject: dict[str, Any],
    subject_sha256: str,
    nonce: str,
    digest_sha256: str,
    status: str,
    existing: tuple[str, str, str] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": CLAIM_SCHEMA,
        "replay_scope": MULTI_HOST,
        "backend": BACKEND,
        "namespace": namespace,
        "approval_id": approval_id,
        "subject": dict(subject),
        "subject_sha256": subject_sha256,
        "nonce": nonce,
        "digest_sha256": digest_sha256,
        "status": status,
    }
    if existing is not None:
        value["existing_subject_sha256"] = existing[0]
        value["existing_nonce"] = existing[1]
        value["existing_digest_sha256"] = existing[2]
    value["receipt_id"] = "mrc_" + _sha256_text(_canonical_json(value))
    return value


class PostgresApprovalReplayAuthority:
    """PostgreSQL-backed replay authority with multi-host CAS semantics."""

    replay_scope = MULTI_HOST
    backend = BACKEND

    def __init__(
        self,
        dsn: str,
        *,
        namespace: str = "human-approval",
        connect: Callable[[str], Any] | None = None,
    ) -> None:
        self.dsn = _dsn(dsn)
        self.namespace = _namespace(namespace)
        if connect is None:
            try:
                module = importlib.import_module("psycopg")
                connect = module.connect
            except (ImportError, AttributeError) as exc:
                raise MultiHostApprovalReplayError(
                    "multi-host replay: psycopg backend unavailable"
                ) from exc
        self._connect = connect
        self._initialize()

    def _open(self) -> Any:
        try:
            return self._connect(self.dsn)
        except Exception as exc:
            raise MultiHostApprovalReplayError(
                "multi-host replay: PostgreSQL connection failed"
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
                "INSERT INTO continuityos_replay_meta(key, value) "
                "VALUES('schema', %s) ON CONFLICT (key) DO NOTHING",
                (SCHEMA,),
            )
            cur.execute(
                "SELECT value FROM continuityos_replay_meta WHERE key='schema'"
            )
            if cur.fetchone() != (SCHEMA,):
                raise MultiHostApprovalReplayError(
                    "multi-host replay: schema identity mismatch"
                )
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
                "multi-host replay: schema initialization failed"
            ) from exc
        finally:
            _close_quietly(cur)
            _close_quietly(con)

    def claim_once(
        self,
        *,
        approval_id: str,
        subject: dict[str, Any],
        nonce: str,
        digest_sha256: str,
    ) -> dict[str, Any]:
        identifier = _approval_id(approval_id)
        subject_json = _canonical_json(subject)
        subject_sha256 = _sha256_text(subject_json)
        nonce_value = _hex64("nonce", nonce)
        digest_value = _hex64("digest_sha256", digest_sha256)
        con = self._open()
        cur = None
        try:
            cur = con.cursor()
            cur.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            cur.execute(
                "SELECT value FROM continuityos_replay_meta WHERE key='schema'"
            )
            if cur.fetchone() != (SCHEMA,):
                raise MultiHostApprovalReplayError(
                    "multi-host replay: schema identity mismatch"
                )
            cur.execute(
                "INSERT INTO continuityos_approval_claims("
                "namespace, approval_id, subject_json, subject_sha256, nonce, digest_sha256"
                ") VALUES(%s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (namespace, approval_id) DO NOTHING "
                "RETURNING subject_json, subject_sha256, nonce, digest_sha256",
                (
                    self.namespace,
                    identifier,
                    subject_json,
                    subject_sha256,
                    nonce_value,
                    digest_value,
                ),
            )
            inserted = cur.fetchone()
            expected_inserted = (subject_json, subject_sha256, nonce_value, digest_value)
            if inserted is not None:
                if tuple(inserted) != expected_inserted:
                    raise MultiHostApprovalReplayError(
                        "multi-host replay: inserted claim readback mismatch"
                    )
                con.commit()
                return _receipt(
                    namespace=self.namespace,
                    approval_id=identifier,
                    subject=dict(subject),
                    subject_sha256=subject_sha256,
                    nonce=nonce_value,
                    digest_sha256=digest_value,
                    status=CLAIMED,
                )
            cur.execute(
                "SELECT subject_json, subject_sha256, nonce, digest_sha256 "
                "FROM continuityos_approval_claims "
                "WHERE namespace=%s AND approval_id=%s",
                (self.namespace, identifier),
            )
            existing_row = cur.fetchone()
            if existing_row is None:
                raise MultiHostApprovalReplayError(
                    "multi-host replay: conflict row disappeared"
                )
            con.commit()
            existing_json, existing_subject_sha, existing_nonce, existing_digest = existing_row
            same = (
                existing_json == subject_json
                and existing_subject_sha == subject_sha256
                and existing_nonce == nonce_value
                and existing_digest == digest_value
            )
            return _receipt(
                namespace=self.namespace,
                approval_id=identifier,
                subject=dict(subject),
                subject_sha256=subject_sha256,
                nonce=nonce_value,
                digest_sha256=digest_value,
                status=ALREADY_CONSUMED if same else CONFLICT,
                existing=(existing_subject_sha, existing_nonce, existing_digest),
            )
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
                "multi-host replay: claim failed"
            ) from exc
        finally:
            _close_quietly(cur)
            _close_quietly(con)


__all__ = [
    "SCHEMA", "CLAIM_SCHEMA", "MULTI_HOST", "BACKEND",
    "CLAIMED", "ALREADY_CONSUMED", "CONFLICT",
    "MultiHostApprovalReplayError", "PostgresApprovalReplayAuthority",
]
