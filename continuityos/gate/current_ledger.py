"""Public Ledger adapter that becomes read-only under verified current authority."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List

from ..current_effect_boundary import (
    CurrentEffectBoundaryError,
    MODE_CURRENT,
    MODE_LEGACY,
    inspect_current_session,
)
from .ledger import GENESIS, HASH_SCHEME, Ledger as _LegacyLedger


class Ledger:
    """Backward-compatible Ledger with monotonic current-session read-only mode."""

    def __init__(self, path: str = "continuity_ledger.db"):
        self._legacy: _LegacyLedger | None = None
        state = inspect_current_session()
        if state["mode"] == MODE_LEGACY:
            self._legacy = _LegacyLedger(path)
            self.con = self._legacy.con
            self.path = path
            self.read_only = False
            return
        if state["mode"] != MODE_CURRENT:
            raise CurrentEffectBoundaryError("ledger.open", state)

        normalized = os.path.normcase(
            os.path.realpath(os.path.abspath(os.path.expanduser(path)))
        )
        if not os.path.isfile(normalized):
            raise FileNotFoundError(normalized)
        self.path = normalized
        self.read_only = True
        self.con = sqlite3.connect(
            Path(normalized).as_uri() + "?mode=ro",
            uri=True,
            timeout=30.0,
        )
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA query_only=ON")

    def append(self, kind: str, payload: Dict[str, Any]) -> str:
        if self._legacy is not None:
            return self._legacy.append(kind, payload)
        state = inspect_current_session()
        raise CurrentEffectBoundaryError("ledger.append", state)

    def verify(self) -> Dict[str, Any]:
        if self._legacy is not None:
            return self._legacy.verify()
        prev = GENESIS
        n = 0
        for row in self.con.execute("SELECT * FROM events ORDER BY id"):
            digest = hashlib.sha256(
                (prev + row["kind"] + ("%.6f" % row["ts"]) + row["payload"]).encode("utf-8")
            ).hexdigest()
            if digest != row["hash"] or row["prev_hash"] != prev:
                return {"ok": False, "broken_at": row["id"], "verified": n}
            prev = row["hash"]
            n += 1
        return {"ok": True, "verified": n}

    @staticmethod
    def _event_dict(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "ts": row["ts"],
            "ts_text": "%.6f" % row["ts"],
            "kind": row["kind"],
            "payload": json.loads(row["payload"]),
            "payload_json": row["payload"],
            "prev_hash": row["prev_hash"],
            "hash": row["hash"],
            "hash_scheme": HASH_SCHEME,
        }

    def export(self, limit: int = 100) -> List[Dict[str, Any]]:
        if self._legacy is not None:
            return self._legacy.export(limit)
        rows = self.con.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._event_dict(row) for row in rows]

    def event(self, event_hash: str):
        if self._legacy is not None:
            return self._legacy.event(event_hash)
        row = self.con.execute(
            "SELECT * FROM events WHERE hash=? LIMIT 1", (event_hash,)
        ).fetchone()
        return self._event_dict(row) if row is not None else None

    def close(self) -> None:
        if self._legacy is not None:
            self._legacy.close()
        else:
            self.con.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
