"""Local continuity state and explicit, scoped handoff snapshots.

Scope selects context; it is not an authentication boundary. A snapshot digest
binds local record bytes, not their origin, execution or authority.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from typing import Any, Dict, List, Optional

from .memory import Memory

FRONTIER_KINDS = ("trunk", "cash", "lab", "parked")
LIFECYCLES = ("ACTIVE", "PAUSED", "DONE")


def _scope_value(value: Optional[str], name: str) -> Optional[str]:
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ValueError(f"{name} must be a non-empty string or None")
    return value


def _matches_scope(meta: Dict[str, Any], scope: Dict[str, Optional[str]],
                   *, include_global: bool = False) -> bool:
    exact = all(meta.get(key) == value for key, value in scope.items())
    global_record = all(meta.get(key) is None for key in ("project", "subject"))
    return exact or (include_global and global_record)


def _current_record(meta: Dict[str, Any], created_at: float, now: float) -> bool:
    """Exclude retired, future, expired and malformed temporal records."""
    if "superseded_by" in meta or meta.get("active") is False:
        return False
    if str(meta.get("status", "")).upper() in {
        "SUPERSEDED", "REVOKED", "REJECTED", "DELETED", "EXPIRED",
    }:
        return False
    start = meta.get("valid_from", created_at)
    end = meta.get("valid_to")
    for value in (start, end):
        if value is not None and (isinstance(value, bool)
                                  or not isinstance(value, (int, float))
                                  or not math.isfinite(value)):
            return False
    return start is not None and start <= now and (end is None or now < end)


def _unreviewed_record(meta: Dict[str, Any]) -> bool:
    return (meta.get("accepted") is False
            or meta.get("review_status") in {"UNREVIEWED", "REJECTED"}
            or meta.get("admission_status") in {"CANDIDATE", "QUARANTINED"})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def assess_continuity_health(*, memory_count: int, canon_count: int,
                             frontiers: Dict[str, Any], loops: List[Dict[str, Any]],
                             last_checkpoint: Optional[Dict[str, Any]], now: float,
                             max_open_loops: int = 7, checkpoint_stale_hours: float = 48,
                             lifecycle: Optional[str] = None,
                             scope: Optional[Dict[str, Optional[str]]] = None) -> Dict[str, Any]:
    """Pure shared assessment for API/CLI status and Continuity.doctor.

    Presence is deliberately distinct from provenance or proof verification.
    Default budgets retain the legacy caller policy; they are not universal gates.
    """
    if isinstance(max_open_loops, bool) or not isinstance(max_open_loops, int) or max_open_loops < 0:
        raise ValueError("max_open_loops must be a non-negative integer")
    if isinstance(checkpoint_stale_hours, bool) or not isinstance(checkpoint_stale_hours, (int, float)) \
            or not math.isfinite(checkpoint_stale_hours) or checkpoint_stale_hours < 0:
        raise ValueError("checkpoint_stale_hours must be a finite non-negative number")
    last = last_checkpoint
    meta = last.get("meta", {}) if last else {}
    state = lifecycle if lifecycle is not None else meta.get("lifecycle", "ACTIVE")
    if state not in LIFECYCLES:
        raise ValueError(f"lifecycle must be one of {LIFECYCLES}")
    checks: List[Dict[str, Any]] = []

    def chk(ok: bool, name: str, detail: str) -> None:
        checks.append({"ok": bool(ok), "check": name, "detail": detail})

    if state == "ACTIVE":
        chk("cash" in frontiers, "cash_frontier_set", frontiers.get("cash", "— not set"))
        chk("trunk" in frontiers, "trunk_set", frontiers.get("trunk", "— not set"))
    chk(len(loops) <= max_open_loops, "open_loops_bounded", f"{len(loops)} open (max {max_open_loops})")
    chk(last is not None, "checkpoint_present", "checkpoint present" if last else "no checkpoint yet")
    if state == "ACTIVE":
        stamp = meta.get("ts", last.get("created_at") if last else None)
        valid_stamp = isinstance(stamp, (int, float)) and not isinstance(stamp, bool) and math.isfinite(stamp)
        age_h = (now - stamp) / 3600 if valid_stamp else None
        chk(age_h is not None and 0 <= age_h <= checkpoint_stale_hours, "checkpoint_fresh",
            f"{age_h:.1f}h old" if age_h is not None else "checkpoint time unavailable")
    proof = meta.get("proof")
    proof_present = isinstance(proof, str) and bool(proof.strip())
    chk(proof_present, "proof_reference_present",
        "reference present; content/existence not verified" if proof_present else "no proof reference")
    chk(memory_count > 0, "memory_nonempty", f"{memory_count} scoped records")
    chk(canon_count > 0, "canon_present", f"{canon_count} applicable canon record(s)")
    if state == "DONE":
        chk(not loops, "done_has_no_open_loops", f"{len(loops)} open loop(s)")
    passed = sum(check["ok"] for check in checks)
    return {"healthy": passed == len(checks), "passed": passed, "total": len(checks),
            "checks": checks, "lifecycle": state,
            "scope": scope if scope is not None else {"project": None, "subject": None},
            "proof_verification": "NOT_PERFORMED", "authority_granted": False}


class Continuity:
    def __init__(self, memory: Optional[Memory] = None, db: str = "continuityos.db",
                 *, read_only: bool = False, project: Optional[str] = None,
                 subject: Optional[str] = None):
        self.project = _scope_value(project, "project")
        self.subject = _scope_value(subject, "subject")
        self.m = memory if memory is not None else Memory(db, read_only=read_only)

    def _scope(self, project: Optional[str] = None,
               subject: Optional[str] = None) -> Dict[str, Optional[str]]:
        """None inherits instance scope; an unscoped instance selects legacy rows."""
        return {"project": _scope_value(project, "project") if project is not None else self.project,
                "subject": _scope_value(subject, "subject") if subject is not None else self.subject}

    def _meta(self, project: Optional[str], subject: Optional[str], **values: Any) -> Dict[str, Any]:
        return {**values, **{key: value for key, value in self._scope(project, subject).items()
                             if value is not None}}

    def add_canon(self, text: str, tags: Optional[List[str]] = None, *,
                  project: Optional[str] = None, subject: Optional[str] = None) -> int:
        return self.m.remember(text, namespace="canon", tags=tags or [],
                               meta=self._meta(project, subject))

    def canon(self, *, project: Optional[str] = None,
              subject: Optional[str] = None, now: Optional[float] = None) -> List[Dict[str, Any]]:
        return self._dump("canon", current_only=True, include_global=True,
                          project=project, subject=subject, now=now)

    def set_frontier(self, kind: str, item: str, *, project: Optional[str] = None,
                     subject: Optional[str] = None) -> int:
        kind = kind.lower()
        if kind not in FRONTIER_KINDS:
            raise ValueError(f"kind must be one of {FRONTIER_KINDS}")
        return self.m.remember(item, namespace="frontier", tags=[kind],
                               meta=self._meta(project, subject, kind=kind, ts=time.time()))

    @staticmethod
    def _latest_frontiers(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        latest: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            kind = row["meta"].get("kind") or (row["tags"][0] if row["tags"] else "parked")
            previous = latest.get(kind)
            if previous is None or (row["meta"].get("ts", 0), row["id"]) > (
                previous["meta"].get("ts", 0), previous["id"],
            ):
                latest[kind] = row
        return [latest[kind] for kind in sorted(latest)]

    def frontiers(self, *, project: Optional[str] = None,
                  subject: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Optional[str]]:
        rows = self._latest_frontiers(self._dump("frontier", current_only=True,
                                                  project=project, subject=subject, now=now))
        return {row["meta"].get("kind") or (row["tags"][0] if row["tags"] else "parked"): row["text"]
                for row in rows}

    def add_loop(self, text: str, tags: Optional[List[str]] = None, *,
                 project: Optional[str] = None, subject: Optional[str] = None) -> int:
        return self.m.remember(text, namespace="loop", tags=(tags or []) + ["open"],
                               meta=self._meta(project, subject, open=True,
                                               status="OPEN", ts=time.time()))

    def close_loop(self, loop_id: int, *, result: str = "", proof: str = "",
                   project: Optional[str] = None, subject: Optional[str] = None) -> bool:
        """Close without deleting identity/text; retries preserve the first closure.

        This records a local outcome, not verification of an external effect.
        """
        if type(loop_id) is not int or loop_id < 1:
            raise ValueError("loop_id must be a positive integer")
        if not isinstance(result, str) or not isinstance(proof, str):
            raise ValueError("result and proof must be strings")
        with self.m.store.transaction():
            row = self.m.store.get(loop_id)
            if row is None or row["namespace"] != "loop":
                return False
            if not _matches_scope(json.loads(row["meta"]), self._scope(project, subject)):
                return False
            return self.m.store.close_loop(loop_id, result=result, proof=proof)

    @staticmethod
    def _closed(row: Dict[str, Any]) -> bool:
        return row["meta"].get("open") is False or row["meta"].get("status") == "CLOSED"

    def open_loops(self, *, project: Optional[str] = None,
                   subject: Optional[str] = None) -> List[Dict[str, Any]]:
        return [row for row in self._dump("loop", current_only=True,
                                           project=project, subject=subject) if not self._closed(row)]

    def closed_loops(self, *, project: Optional[str] = None,
                     subject: Optional[str] = None) -> List[Dict[str, Any]]:
        return [row for row in self._dump("loop", project=project, subject=subject)
                if self._closed(row) and not _unreviewed_record(row["meta"])]

    def checkpoint(self, summary: str, next_action: str, proof: str = "", *,
                   project: Optional[str] = None, subject: Optional[str] = None,
                   lifecycle: str = "ACTIVE") -> int:
        if lifecycle not in LIFECYCLES:
            raise ValueError(f"lifecycle must be one of {LIFECYCLES}")
        text = f"DELTA: {summary} | NEXT: {next_action}" + (f" | PROOF: {proof}" if proof else "")
        return self.m.remember(text, namespace="checkpoint", tags=["checkpoint"],
                               meta=self._meta(project, subject, ts=time.time(), summary=summary,
                                               next=next_action, proof=proof, lifecycle=lifecycle))

    def last_checkpoint(self, *, project: Optional[str] = None,
                         subject: Optional[str] = None) -> Optional[Dict[str, Any]]:
        rows = self._dump("checkpoint", current_only=True, project=project, subject=subject)
        return max(rows, key=lambda row: (row["meta"].get("ts", 0), row["id"]), default=None)

    def doctor(self, max_open_loops: int = 7, checkpoint_stale_hours: float = 48, *,
               project: Optional[str] = None, subject: Optional[str] = None,
               lifecycle: Optional[str] = None) -> Dict[str, Any]:
        """Report literal state checks; a proof reference is not verified proof."""
        with self.m.store.read_snapshot():
            return assess_continuity_health(
                memory_count=len(self._dump(None, project=project, subject=subject)),
                canon_count=len(self.canon(project=project, subject=subject)),
                frontiers=self.frontiers(project=project, subject=subject),
                loops=self.open_loops(project=project, subject=subject),
                last_checkpoint=self.last_checkpoint(project=project, subject=subject),
                now=time.time(), max_open_loops=max_open_loops,
                checkpoint_stale_hours=checkpoint_stale_hours,
                lifecycle=lifecycle, scope=self._scope(project, subject))

    def handoff_snapshot(self, *, project: Optional[str] = None, subject: Optional[str] = None,
                         max_items: Optional[int] = None, max_bytes: Optional[int] = None) -> Dict[str, Any]:
        """Return all applicable state, or a budget HOLD with no partial payload.

        Limits are caller-supplied. The payload digest binds local bytes, not
        source authority. Reading does not grant permission for a next action.
        """
        for name, value in (("max_items", max_items), ("max_bytes", max_bytes)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError(f"{name} must be a non-negative integer or None")
        scope = self._scope(project, subject)
        store = self.m.store
        # Pin local SQLite reads together; this is not a provider/model transaction.
        with store.read_snapshot():
            store.con.execute("SELECT id FROM items LIMIT 1").fetchone()
            observed_at = time.time()
            canon = self._dump("canon", current_only=True, include_global=True,
                               project=project, subject=subject, now=observed_at)
            frontiers = self._latest_frontiers(self._dump("frontier", current_only=True,
                                                           project=project, subject=subject, now=observed_at))
            loops = self._dump("loop", current_only=True, project=project, subject=subject, now=observed_at)
            closed = [row for row in self._dump("loop", project=project, subject=subject)
                      if self._closed(row) and not _unreviewed_record(row["meta"])]
            checkpoints = self._dump("checkpoint", current_only=True, project=project,
                                     subject=subject, now=observed_at)
            checkpoint = max(checkpoints, key=lambda row: (row["meta"].get("ts", 0), row["id"]), default=None)
            payload = {"canon": canon, "frontiers": frontiers,
                       "open_loops": [row for row in loops if not self._closed(row)],
                       "closed_loops": closed, "last_checkpoint": checkpoint}
            candidate_counts = {}
            for row in self._dump(None, include_global=True, project=project, subject=subject):
                namespace = row["namespace"]
                if namespace not in ("canon", "frontier", "loop", "checkpoint"):
                    continue
                if not _matches_scope(row["meta"], scope, include_global=namespace == "canon"):
                    continue
                if _unreviewed_record(row["meta"]) and _current_record(row["meta"], row["created_at"], observed_at):
                    candidate_counts[namespace] = candidate_counts.get(namespace, 0) + 1
        counts = {name: len(value) if isinstance(value, list) else int(value is not None)
                  for name, value in payload.items()}
        encoded = _canonical(payload)
        binding = _canonical({"schema": "continuityos.handoff_snapshot/v1", "scope": scope,
                              "payload": payload, "excluded_candidate_counts": candidate_counts})
        reasons = []
        if max_items is not None and sum(counts.values()) > max_items:
            reasons.append("ITEM_BUDGET_EXCEEDED")
        if max_bytes is not None and len(encoded) > max_bytes:
            reasons.append("BYTE_BUDGET_EXCEEDED")
        return {"schema": "continuityos.handoff_snapshot/v1", "scope": scope,
                "status": "HOLD" if reasons else "READY", "complete": not reasons,
                "observed_at": observed_at, "snapshot_sha256": hashlib.sha256(binding).hexdigest(),
                "counts": counts, "payload_bytes": len(encoded),
                "excluded_candidate_counts": candidate_counts,
                "coverage_kind": "APPLICABLE_CURRENT_STATE_AND_RECORDED_CLOSURES",
                "overflow": {"reasons": reasons, "max_items": max_items, "max_bytes": max_bytes,
                             "byte_budget_basis": "CANONICAL_PAYLOAD_UTF8"},
                "payload": None if reasons else payload, "origin_verified": False,
                "authority_granted": False}

    def handoff(self, *, project: Optional[str] = None, subject: Optional[str] = None,
                max_items: Optional[int] = None, max_bytes: Optional[int] = None) -> str:
        snapshot = self.handoff_snapshot(project=project, subject=subject,
                                          max_items=max_items, max_bytes=max_bytes)
        return self.render_handoff(snapshot)

    @staticmethod
    def render_handoff(snapshot: Dict[str, Any]) -> str:
        """Render an already captured snapshot without rereading mutable state."""
        out = ["# ContinuityOS handoff pack",
               f"Scope: {json.dumps(snapshot['scope'], ensure_ascii=False, sort_keys=True)}",
               f"Snapshot: {snapshot['snapshot_sha256']} | status: {snapshot['status']}"]
        if not snapshot["complete"]:
            out.append("HOLD: " + ", ".join(snapshot["overflow"]["reasons"]) + "; no partial context emitted.")
            out.append("Counts: " + json.dumps(snapshot["counts"], sort_keys=True))
            return "\n".join(out)
        payload = snapshot["payload"]
        out.append("\n## Canon (non-negotiable)")
        out += [f"- [mem:{row['id']}] {row['text']}" for row in payload["canon"]] or ["- (none)"]
        out.append("\n## Frontiers")
        out += [f"- {row['meta'].get('kind', 'parked')}: {row['text']} [mem:{row['id']}]"
                for row in payload["frontiers"]] or ["- (none)"]
        out.append("\n## Open loops")
        out += [f"- [#{row['id']}] {row['text']}" for row in payload["open_loops"]] or ["- (none)"]
        out.append("\n## Closed loops (recorded outcomes; external effects not verified)")
        out += [f"- [#{row['id']}] {row['text']} | RESULT: {row['meta'].get('result', '')}"
                f" | PROOF: {row['meta'].get('proof', '')}" for row in payload["closed_loops"]] or ["- (none)"]
        out.append("\n## Last checkpoint")
        checkpoint = payload["last_checkpoint"]
        out.append(f"- [mem:{checkpoint['id']}] {checkpoint['text']}" if checkpoint else "- (none)")
        if checkpoint:
            out.append("Lifecycle: " + checkpoint["meta"].get("lifecycle", "ACTIVE"))
        out.append("\nCounts: " + json.dumps(snapshot["counts"], sort_keys=True) + "; omitted: 0")
        out.append("Unreviewed/excluded candidates: " + json.dumps(snapshot["excluded_candidate_counts"], sort_keys=True))
        return "\n".join(out)

    def _dump(self, namespace: Optional[str], *, current_only: bool = False,
              include_global: bool = False, project: Optional[str] = None,
              subject: Optional[str] = None, now: Optional[float] = None) -> List[Dict[str, Any]]:
        scope = self._scope(project, subject)
        observed_at = time.time() if now is None else now
        rows = self.m.store.all_with_vecs(namespace=namespace)
        result = []
        for row in rows:
            meta = json.loads(row["meta"])
            if not _matches_scope(meta, scope, include_global=include_global):
                continue
            if current_only and not _current_record(meta, row["created_at"], observed_at):
                continue
            if current_only and _unreviewed_record(meta):
                continue
            result.append({"id": row["id"], "text": row["text"], "namespace": row["namespace"],
                           "tags": json.loads(row["tags"]), "meta": meta, "created_at": row["created_at"],
                           "version": row["version"], "memory_ref": f"mem:{row['id']}"})
        return sorted(result, key=lambda row: row["id"])
