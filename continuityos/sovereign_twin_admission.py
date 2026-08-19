"""Append-only shadow memory admission queue for Sovereign Twin.

Proposals are local evidence only. They do not mutate ContinuityOS canonical memory.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import time
from typing import Any, Iterable, Mapping

EXECUTION_AUTHORITY = "NONE"
SCHEMA = "continuityos.sovereign-twin.memory-admission/v1"


class AdmissionQueueError(ValueError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class ShadowMemoryAdmissionQueue:
    """Hash-chained JSONL queue; PENDING proposals never auto-write canonical memory."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _rows(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AdmissionQueueError(f"invalid admission JSON at line {lineno}") from exc
                if not isinstance(row, dict):
                    raise AdmissionQueueError(f"invalid admission row at line {lineno}")
                rows.append(row)
        return rows

    def verify(self) -> dict[str, Any]:
        rows = self._rows()
        prev = None
        for seq, row in enumerate(rows, 1):
            required = {"schema", "seq", "kind", "ts", "payload", "prev_hash", "event_hash"}
            if set(row) != required:
                return {"ok": False, "count": len(rows), "error": f"shape mismatch at seq {seq}"}
            if row["schema"] != SCHEMA or row["seq"] != seq or row["prev_hash"] != prev:
                return {"ok": False, "count": len(rows), "error": f"chain mismatch at seq {seq}"}
            body = {k: row[k] for k in ("schema", "seq", "kind", "ts", "payload", "prev_hash")}
            if _sha(body) != row["event_hash"]:
                return {"ok": False, "count": len(rows), "error": f"hash mismatch at seq {seq}"}
            prev = row["event_hash"]
        return {"ok": True, "count": len(rows), "head_hash": prev}

    def propose(
        self,
        text: str,
        *,
        namespace: str = "notes",
        tags: Iterable[str] = (),
        source: str = "LOCAL_TWIN",
        evidence_refs: Iterable[str] = (),
        ts: float | None = None,
    ) -> dict[str, Any]:
        text = str(text).strip()
        namespace = str(namespace).strip()
        if not text or not namespace:
            raise AdmissionQueueError("text and namespace are required")
        checked = self.verify()
        if not checked["ok"]:
            raise AdmissionQueueError(f"refusing append to invalid queue: {checked['error']}")
        event_ts = time.time() if ts is None else float(ts)
        if not math.isfinite(event_ts):
            raise AdmissionQueueError("proposal timestamp must be finite")
        payload = {
            "text": text,
            "namespace": namespace,
            "tags": tuple(dict.fromkeys(str(x).strip() for x in tags if str(x).strip())),
            "source": str(source).strip() or "LOCAL_TWIN",
            "evidence_refs": tuple(
                dict.fromkeys(str(x).strip() for x in evidence_refs if str(x).strip())
            ),
            "status": "PENDING",
            "canonical_memory_mutated": False,
            "execution_authority": EXECUTION_AUTHORITY,
            "can_execute": False,
        }
        payload["proposal_id"] = _sha({"ts": event_ts, **payload})
        rows = self._rows()
        body = {
            "schema": SCHEMA,
            "seq": len(rows) + 1,
            "kind": "MEMORY_ADMISSION_PROPOSED",
            "ts": event_ts,
            "payload": payload,
            "prev_hash": rows[-1]["event_hash"] if rows else None,
        }
        event = {**body, "event_hash": _sha(body)}
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(_canonical(event) + "\n")
            fh.flush()
        return event

    def pending(self) -> list[dict[str, Any]]:
        return [
            dict(row["payload"])
            for row in self._rows()
            if row.get("kind") == "MEMORY_ADMISSION_PROPOSED"
            and isinstance(row.get("payload"), Mapping)
            and row["payload"].get("status") == "PENDING"
        ]
