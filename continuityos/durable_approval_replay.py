"""Durable local replay protection for authenticated Human approvals.

R18 supplies a stdlib-only SQLite implementation of the R17 ``consume_once``
contract. It is durable across process restarts and atomic across cooperating
processes on one host. It does not provide distributed multi-node consensus.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Final

from .persistent_governance_store import resolve_persistent_governance_store_path

SCHEMA = "continuityos.durable_approval_replay/v1"
_APPROVAL_ID_RE: Final = re.compile(r"^hap_[0-9a-f]{64}$")
_DEFAULT_BUSY_TIMEOUT_MS: Final = 30_000


class DurableApprovalReplayError(RuntimeError):
    """Raised when durable replay state cannot be trusted or updated safely."""


def _approval_id(value: object) -> str:
    if type(value) is not str or _APPROVAL_ID_RE.fullmatch(value) is None:
        raise ValueError("durable approval replay: invalid approval_id")
    return value


def _busy_timeout(value: object) -> int:
    if type(value) is not int or value < 1 or value > 300_000:
        raise ValueError("durable approval replay: invalid busy_timeout_ms")
    return value


class SQLiteApprovalReplayGuard:
    """File-backed R17 replay guard for one-host multi-process deployments."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = _DEFAULT_BUSY_TIMEOUT_MS,
    ) -> None:
        self.path = str(resolve_persistent_governance_store_path(
            path, label="durable approval replay"
        ))
        self.busy_timeout_ms = _busy_timeout(busy_timeout_ms)
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self._initialize()
        except (OSError, sqlite3.Error) as exc:
            raise DurableApprovalReplayError(
                "durable approval replay: storage initialization failed"
            ) from exc

    def _connect(self, *, require_wal: bool = True) -> sqlite3.Connection:
        con = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        try:
            con.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            con.execute("PRAGMA synchronous=FULL")
            if require_wal:
                mode = con.execute("PRAGMA journal_mode").fetchone()[0]
                if str(mode).lower() != "wal":
                    raise DurableApprovalReplayError(
                        f"durable approval replay: journal mode drift: {mode}"
                    )
            return con
        except Exception:
            con.close()
            raise

    @staticmethod
    def _assert_schema(con: sqlite3.Connection) -> None:
        row = con.execute(
            "SELECT value FROM replay_meta WHERE key='schema'"
        ).fetchone()
        if row != (SCHEMA,):
            raise DurableApprovalReplayError(
                "durable approval replay: schema identity mismatch"
            )

    def _initialize(self) -> None:
        con = self._connect(require_wal=False)
        try:
            mode = con.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise DurableApprovalReplayError(
                    f"durable approval replay: SQLite WAL unavailable: {mode}"
                )
            con.execute("PRAGMA synchronous=FULL")
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "CREATE TABLE IF NOT EXISTS replay_meta("
                "key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS consumed_approvals("
                "approval_id TEXT PRIMARY KEY, "
                "consumed_marker INTEGER NOT NULL CHECK(consumed_marker = 1)"
                ") WITHOUT ROWID"
            )
            row = con.execute(
                "SELECT value FROM replay_meta WHERE key='schema'"
            ).fetchone()
            if row is None:
                con.execute(
                    "INSERT INTO replay_meta(key, value) VALUES('schema', ?)",
                    (SCHEMA,),
                )
            elif row[0] != SCHEMA:
                raise DurableApprovalReplayError(
                    "durable approval replay: schema identity mismatch"
                )
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def consume_once(self, approval_id: str) -> bool:
        """Atomically consume one approval ID; return False only if already consumed."""
        identifier = _approval_id(approval_id)
        con: sqlite3.Connection | None = None
        try:
            con = self._connect()
            con.execute("BEGIN IMMEDIATE")
            self._assert_schema(con)
            try:
                con.execute(
                    "INSERT INTO consumed_approvals(approval_id, consumed_marker) VALUES(?, 1)",
                    (identifier,),
                )
            except sqlite3.IntegrityError as exc:
                row = con.execute(
                    "SELECT consumed_marker FROM consumed_approvals WHERE approval_id=?",
                    (identifier,),
                ).fetchone()
                con.rollback()
                if row == (1,):
                    return False
                raise DurableApprovalReplayError(
                    "durable approval replay: integrity failure"
                ) from exc
            con.commit()
            return True
        except DurableApprovalReplayError:
            raise
        except (OSError, sqlite3.Error) as exc:
            if con is not None:
                try:
                    con.rollback()
                except sqlite3.Error:
                    pass
            raise DurableApprovalReplayError(
                "durable approval replay: storage consume failed"
            ) from exc
        finally:
            if con is not None:
                con.close()

    def contains(self, approval_id: str) -> bool:
        """Return whether an approval ID has already been durably consumed."""
        identifier = _approval_id(approval_id)
        con: sqlite3.Connection | None = None
        try:
            con = self._connect()
            self._assert_schema(con)
            row = con.execute(
                "SELECT consumed_marker FROM consumed_approvals WHERE approval_id=?",
                (identifier,),
            ).fetchone()
            if row is None:
                return False
            if row != (1,):
                raise DurableApprovalReplayError(
                    "durable approval replay: stored marker invalid"
                )
            return True
        except DurableApprovalReplayError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise DurableApprovalReplayError(
                "durable approval replay: storage read failed"
            ) from exc
        finally:
            if con is not None:
                con.close()


__all__ = [
    "SCHEMA",
    "DurableApprovalReplayError",
    "SQLiteApprovalReplayGuard",
]
