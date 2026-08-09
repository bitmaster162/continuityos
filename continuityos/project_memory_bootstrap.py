"""Deterministic fresh-project bootstrap for shadow Common Operational Memory.

R38 removes imperative/manual seeding. One declarative manifest binds project facts
to exact local evidence files. A separate authorization binds the raw manifest SHA,
target path and row counts. Bootstrap is effectful, so any declared current R64
session is refused before target creation.

A bootstrap may create claims and PROPOSED decisions only. Accepted/HOLD/rejected
truth remains outside this seed path. Existing databases are never overwritten;
subsequent synchronization uses the R36 proposal + R37 authorized apply path.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Mapping, Sequence

from . import current_effect_boundary as boundary
from .operational_memory import (
    EVIDENCE_STATES,
    OperationalMemory,
    _canonical_json,
    _nonempty,
    _normalize_time,
    normalize_evidence_refs,
    strict_json_loads,
)

MANIFEST_SCHEMA = "continuityos.operational_memory.project_bootstrap_manifest/v1"
AUTH_SCHEMA = "continuityos.operational_memory.project_bootstrap_authorization/v1"
RECEIPT_SCHEMA = "continuityos.operational_memory.project_bootstrap_receipt/v1"
AUTH_DECISION = "APPROVE_SHADOW_PROJECT_MEMORY_BOOTSTRAP"
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_FILES = 256
MAX_CLAIMS = 1024
MAX_PROPOSED_DECISIONS = 256
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _effects(*, wrote: bool = False) -> dict[str, Any]:
    return {
        "operational_memory_write": bool(wrote),
        "filesystem_write": bool(wrote),
        "accepted_truth_modified": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "deployment": False,
        "agent_dispatch": False,
        "external_message": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def _receipt(
    terminal: str,
    reason: str,
    *,
    project_id: str | None = None,
    target_db: str | None = None,
    errors: Sequence[str] | None = None,
    wrote: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "terminal": terminal,
        "reason": reason,
        "project_id": project_id,
        "target_db": target_db,
        "errors": list(errors or []),
        "shadow_memory_bootstrap": "CREATED" if wrote else "NOT_CREATED",
        "accepted_truth_modified": False,
        "execution_authorized": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "effects": _effects(wrote=wrote),
        **extra,
    }


def _require_sha(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not SHA_RE.fullmatch(text):
        raise ValueError(f"{label}: invalid SHA-256")
    return text


def _is_reparse(path: Path) -> bool:
    try:
        attrs = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _stable_read(path: Path, label: str, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> bytes:
    path = Path(path).expanduser().absolute()
    if path.is_symlink() or _is_reparse(path):
        raise ValueError(f"{label}: symlink/reparse refused")
    try:
        before = path.stat()
    except OSError as exc:
        raise ValueError(f"{label}: missing") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label}: not a regular file")
    if before.st_size > max_bytes:
        raise ValueError(f"{label}: too large")
    first = path.read_bytes()
    middle = path.stat()
    second = path.read_bytes()
    after = path.stat()
    ids = {
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
        (middle.st_dev, middle.st_ino, middle.st_size, middle.st_mtime_ns),
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
    }
    if len(ids) != 1 or first != second or len(first) != before.st_size:
        raise ValueError(f"{label}: changed during read")
    return first


def _load_object(payload: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = strict_json_loads(payload.decode("utf-8-sig"))
    except Exception as exc:
        raise ValueError(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"{label}: root must be an object")
    return value


def _exact_keys(value: Any, allowed: set[str], required: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label}: must be an object")
    missing = required - set(value)
    extra = set(value) - allowed
    if missing or extra:
        raise ValueError(f"{label}: keys mismatch missing={sorted(missing)} extra={sorted(extra)}")
    return value


def _normalized_target(value: Any) -> Path:
    raw = _nonempty(value, field="target_db")
    if any(ch in raw for ch in ("\x00", "\r", "\n")):
        raise ValueError("target_db contains unsafe control characters")
    return Path(raw).expanduser().absolute()


def _safe_parent(target: Path) -> Path:
    parent = target.parent
    if not parent.exists() or not parent.is_dir():
        raise ValueError("target parent directory must already exist")
    if parent.is_symlink() or _is_reparse(parent):
        raise ValueError("target parent symlink/reparse refused")
    resolved = parent.resolve()
    if resolved != parent.resolve():  # pragma: no cover - defensive readability
        raise ValueError("target parent resolution changed")
    return resolved


def _validate_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {"schema", "project_id", "evidence", "claims", "proposed_decisions", "rationale"}
    required = {"schema", "project_id", "evidence", "claims", "proposed_decisions"}
    _exact_keys(value, allowed, required, "manifest")
    if value.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("manifest schema mismatch")
    project_id = _nonempty(value.get("project_id"), field="project_id")
    rationale = value.get("rationale")
    if rationale is not None:
        rationale = _nonempty(rationale, field="rationale")

    evidence_raw = value.get("evidence")
    if not isinstance(evidence_raw, list) or len(evidence_raw) > MAX_EVIDENCE_FILES:
        raise ValueError(f"evidence must be an array of at most {MAX_EVIDENCE_FILES} rows")
    evidence: list[dict[str, Any]] = []
    evidence_ids: set[str] = set()
    for index, row in enumerate(evidence_raw):
        _exact_keys(
            row,
            {"evidence_id", "sha256", "locator", "kind", "scope"},
            {"evidence_id", "sha256", "locator"},
            f"evidence[{index}]",
        )
        evidence_id = _nonempty(row.get("evidence_id"), field=f"evidence[{index}].evidence_id")
        if evidence_id in evidence_ids:
            raise ValueError(f"duplicate evidence_id: {evidence_id}")
        evidence_ids.add(evidence_id)
        locator = _nonempty(row.get("locator"), field=f"evidence[{index}].locator")
        kind = row.get("kind")
        scope = row.get("scope")
        if kind is not None:
            kind = _nonempty(kind, field=f"evidence[{index}].kind")
        if scope is not None:
            scope = _nonempty(scope, field=f"evidence[{index}].scope")
        evidence.append({
            "evidence_id": evidence_id,
            "sha256": _require_sha(row.get("sha256"), f"evidence[{index}].sha256"),
            "locator": locator,
            "kind": kind,
            "scope": scope,
        })

    claims_raw = value.get("claims")
    if not isinstance(claims_raw, list) or not claims_raw or len(claims_raw) > MAX_CLAIMS:
        raise ValueError(f"claims must contain 1..{MAX_CLAIMS} rows")
    claims: list[dict[str, Any]] = []
    claim_keys: set[tuple[str, str]] = set()
    for index, row in enumerate(claims_raw):
        _exact_keys(
            row,
            {"predicate", "scope", "value", "evidence_state", "evidence_ids", "valid_from", "valid_to", "recorded_at"},
            {"predicate", "scope", "value", "evidence_state", "evidence_ids", "valid_from", "recorded_at"},
            f"claims[{index}]",
        )
        predicate = _nonempty(row.get("predicate"), field=f"claims[{index}].predicate")
        scope = _nonempty(row.get("scope"), field=f"claims[{index}].scope")
        key = (predicate, scope)
        if key in claim_keys:
            raise ValueError(f"duplicate bootstrap claim identity: {predicate}/{scope}")
        claim_keys.add(key)
        state = _nonempty(row.get("evidence_state"), field=f"claims[{index}].evidence_state").upper()
        if state not in EVIDENCE_STATES:
            raise ValueError(f"claims[{index}]: unsupported evidence_state")
        ids = row.get("evidence_ids")
        if not isinstance(ids, list) or not all(isinstance(item, str) and item.strip() for item in ids):
            raise ValueError(f"claims[{index}].evidence_ids must be an array of non-empty strings")
        ids = list(dict.fromkeys(item.strip() for item in ids))
        if any(item not in evidence_ids for item in ids):
            raise ValueError(f"claims[{index}] references unknown evidence_id")
        if state != "UNKNOWN" and not ids:
            raise ValueError(f"claims[{index}] {state} requires evidence")
        valid_from = _normalize_time(_nonempty(row.get("valid_from"), field=f"claims[{index}].valid_from"), field="valid_from")
        valid_to = row.get("valid_to")
        if valid_to is not None:
            valid_to = _normalize_time(_nonempty(valid_to, field=f"claims[{index}].valid_to"), field="valid_to")
            if valid_to <= valid_from:
                raise ValueError(f"claims[{index}].valid_to must be later than valid_from")
        recorded_at = _normalize_time(_nonempty(row.get("recorded_at"), field=f"claims[{index}].recorded_at"), field="recorded_at")
        claims.append({
            "predicate": predicate,
            "scope": scope,
            "value": row.get("value"),
            "evidence_state": state,
            "evidence_ids": ids,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "recorded_at": recorded_at,
        })

    decisions_raw = value.get("proposed_decisions")
    if not isinstance(decisions_raw, list) or len(decisions_raw) > MAX_PROPOSED_DECISIONS:
        raise ValueError(f"proposed_decisions must be an array of at most {MAX_PROPOSED_DECISIONS} rows")
    proposed: list[dict[str, Any]] = []
    for index, row in enumerate(decisions_raw):
        _exact_keys(
            row,
            {"decision_type", "value", "rationale", "evidence_ids", "recorded_at"},
            {"decision_type", "value", "rationale", "evidence_ids", "recorded_at"},
            f"proposed_decisions[{index}]",
        )
        ids = row.get("evidence_ids")
        if not isinstance(ids, list) or not all(isinstance(item, str) and item.strip() for item in ids):
            raise ValueError(f"proposed_decisions[{index}].evidence_ids invalid")
        ids = list(dict.fromkeys(item.strip() for item in ids))
        if any(item not in evidence_ids for item in ids):
            raise ValueError(f"proposed_decisions[{index}] references unknown evidence_id")
        proposed.append({
            "decision_type": _nonempty(row.get("decision_type"), field=f"proposed_decisions[{index}].decision_type"),
            "value": row.get("value"),
            "rationale": _nonempty(row.get("rationale"), field=f"proposed_decisions[{index}].rationale"),
            "evidence_ids": ids,
            "recorded_at": _normalize_time(
                _nonempty(row.get("recorded_at"), field=f"proposed_decisions[{index}].recorded_at"),
                field="recorded_at",
            ),
        })
    return {
        "schema": MANIFEST_SCHEMA,
        "project_id": project_id,
        "evidence": evidence,
        "claims": claims,
        "proposed_decisions": proposed,
        "rationale": rationale,
    }


def _verify_evidence(manifest: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    verified: list[dict[str, Any]] = []
    by_id: dict[str, list[dict[str, Any]]] = {}
    for row in manifest["evidence"]:
        path = Path(row["locator"]).expanduser().absolute()
        payload = _stable_read(path, f"evidence:{row['evidence_id']}")
        actual = _sha_bytes(payload)
        if actual != row["sha256"]:
            raise ValueError(f"evidence SHA mismatch: {row['evidence_id']}")
        ref = {
            "sha256": actual,
            "locator": str(path),
            **({"kind": row["kind"]} if row.get("kind") is not None else {}),
            **({"scope": row["scope"]} if row.get("scope") is not None else {}),
        }
        verified.append({"evidence_id": row["evidence_id"], **ref, "size_bytes": len(payload)})
        by_id[row["evidence_id"]] = [ref]
    verified.sort(key=lambda item: item["evidence_id"])
    return verified, by_id


def _refs(ids: Sequence[str], by_id: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for evidence_id in ids:
        refs.extend(by_id[evidence_id])
    return normalize_evidence_refs(refs)


def _validate_authorization(
    value: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    manifest_sha: str,
    target: Path,
) -> dict[str, Any]:
    expected = {
        "schema", "decision", "manifest_file_sha256", "project_id", "target_db",
        "claim_count", "proposed_decision_count", "authority_class", "authority_id",
        "authority_ref", "bootstrap_recorded_at", "rationale",
    }
    if set(value) != expected:
        raise ValueError(
            f"authorization keys mismatch missing={sorted(expected-set(value))} extra={sorted(set(value)-expected)}"
        )
    if value.get("schema") != AUTH_SCHEMA or value.get("decision") != AUTH_DECISION:
        raise ValueError("authorization identity mismatch")
    if _require_sha(value.get("manifest_file_sha256"), "manifest_file_sha256") != manifest_sha:
        raise ValueError("authorization manifest SHA mismatch")
    if value.get("project_id") != manifest["project_id"]:
        raise ValueError("authorization project mismatch")
    if _normalized_target(value.get("target_db")) != target:
        raise ValueError("authorization target_db mismatch")
    if value.get("claim_count") != len(manifest["claims"]):
        raise ValueError("authorization claim_count mismatch")
    if value.get("proposed_decision_count") != len(manifest["proposed_decisions"]):
        raise ValueError("authorization proposed_decision_count mismatch")
    authority_class = _nonempty(value.get("authority_class"), field="authority_class").upper()
    if authority_class not in {"HUMAN", "DETERMINISTIC_CONTROLLER"}:
        raise ValueError("bootstrap authorization requires HUMAN or DETERMINISTIC_CONTROLLER")
    return {
        **dict(value),
        "authority_class": authority_class,
        "authority_id": _nonempty(value.get("authority_id"), field="authority_id"),
        "authority_ref": _nonempty(value.get("authority_ref"), field="authority_ref"),
        "bootstrap_recorded_at": _normalize_time(
            _nonempty(value.get("bootstrap_recorded_at"), field="bootstrap_recorded_at"),
            field="bootstrap_recorded_at",
        ),
        "rationale": _nonempty(value.get("rationale"), field="rationale"),
    }


def _bootstrap_event(memory: OperationalMemory, *, project_id: str, manifest_sha: str, auth_sha: str) -> dict[str, Any] | None:
    rows = list(memory.con.execute(
        "SELECT event_id,sequence,content_hash,chain_hash,payload_json FROM events "
        "WHERE event_type='PROJECT_MEMORY_BOOTSTRAPPED' AND subject_id=? ORDER BY sequence",
        (project_id,),
    ))
    for row in rows:
        payload = strict_json_loads(row["payload_json"])
        if isinstance(payload, Mapping) and payload.get("manifest_file_sha256") == manifest_sha:
            if payload.get("authorization_file_sha256") != auth_sha:
                raise ValueError("manifest already bootstrapped with different authorization bytes")
            return {
                "event_id": row["event_id"],
                "sequence": int(row["sequence"]),
                "content_hash": row["content_hash"],
                "chain_hash": row["chain_hash"],
            }
    return None


def _cleanup_temp(path: Path) -> None:
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        try:
            if candidate.exists() or candidate.is_symlink():
                candidate.unlink()
        except OSError:
            pass


def bootstrap_project_memory(
    target_db: str | Path,
    manifest_path: str | Path,
    authorization_path: str | Path,
) -> dict[str, Any]:
    """Create one new verified shadow project-memory database; never overwrite."""
    state = boundary.inspect_current_session()
    if state.get("mode") != boundary.MODE_LEGACY:
        return _receipt(
            "PROJECT_MEMORY_BOOTSTRAP_HOLD" if state.get("binding_verified") else "PROJECT_MEMORY_BOOTSTRAP_REVISE",
            "CURRENT_SESSION_EFFECT_FORBIDDEN",
            errors=[str(state.get("reason") or state.get("mode"))],
            current_session=state,
        )
    try:
        target = _normalized_target(str(target_db))
        parent = _safe_parent(target)
        manifest_bytes = _stable_read(Path(manifest_path), "manifest")
        auth_bytes = _stable_read(Path(authorization_path), "authorization")
        manifest_sha = _sha_bytes(manifest_bytes)
        auth_sha = _sha_bytes(auth_bytes)
        manifest = _validate_manifest(_load_object(manifest_bytes, "manifest"))
        verified_evidence, evidence_by_id = _verify_evidence(manifest)
        authorization = _validate_authorization(
            _load_object(auth_bytes, "authorization"),
            manifest=manifest,
            manifest_sha=manifest_sha,
            target=target,
        )
    except Exception as exc:
        return _receipt(
            "PROJECT_MEMORY_BOOTSTRAP_REVISE",
            "BOOTSTRAP_ARTIFACT_INVALID",
            target_db=str(target_db),
            errors=[f"{type(exc).__name__}: {exc}"],
        )

    project_id = manifest["project_id"]
    if target.exists() or target.is_symlink():
        try:
            if target.is_symlink() or _is_reparse(target) or not target.is_file():
                raise ValueError("existing target is unsafe")
            with OperationalMemory(str(target), read_only=True) as memory:
                if memory.verify().get("ok") is not True:
                    raise ValueError("existing target is not a valid OperationalMemory database")
                prior = _bootstrap_event(
                    memory,
                    project_id=project_id,
                    manifest_sha=manifest_sha,
                    auth_sha=auth_sha,
                )
                if prior is None:
                    raise ValueError("target already exists but does not match this bootstrap")
                projection = memory.projection()
            return _receipt(
                "PROJECT_MEMORY_BOOTSTRAP_ALREADY_CREATED",
                "EXACT_BOOTSTRAP_ALREADY_PUBLISHED",
                project_id=project_id,
                target_db=str(target),
                manifest_file_sha256=manifest_sha,
                authorization_file_sha256=auth_sha,
                bootstrap_event=prior,
                projection={
                    "projection_sha256": projection.get("projection_sha256"),
                    "event_cursor": projection.get("event_cursor"),
                    "event_chain_head": projection.get("event_chain_head"),
                },
            )
        except Exception as exc:
            return _receipt(
                "PROJECT_MEMORY_BOOTSTRAP_REVISE",
                "TARGET_ALREADY_EXISTS",
                project_id=project_id,
                target_db=str(target),
                errors=[f"{type(exc).__name__}: {exc}"],
            )

    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.bootstrap-", suffix=".tmp", dir=str(parent))
    os.close(fd)
    temp = Path(temp_name)
    temp.unlink()  # OperationalMemory requires ownership of fresh SQLite creation.
    try:
        with OperationalMemory(str(temp)) as memory:
            for row in manifest["claims"]:
                memory.record_claim(
                    subject_id=project_id,
                    predicate=row["predicate"],
                    value=row["value"],
                    scope=row["scope"],
                    evidence_state=row["evidence_state"],
                    evidence_refs=_refs(row["evidence_ids"], evidence_by_id),
                    valid_from=row["valid_from"],
                    valid_to=row["valid_to"],
                    actor_type="DETERMINISTIC_CONTROLLER",
                    actor_id=authorization["authority_id"],
                    recorded_at=row["recorded_at"],
                )
            proposer = f"bootstrap:{manifest_sha[:24]}"
            for row in manifest["proposed_decisions"]:
                memory.record_decision(
                    subject_id=project_id,
                    decision_type=row["decision_type"],
                    state="PROPOSED",
                    value=row["value"],
                    rationale=row["rationale"],
                    authority_class="AGENT",
                    authority_id=proposer,
                    authority_ref=None,
                    evidence_refs=_refs(row["evidence_ids"], evidence_by_id),
                    recorded_at=row["recorded_at"],
                )
            manifest_ref = {
                "sha256": manifest_sha,
                "locator": str(Path(manifest_path).expanduser().absolute()),
                "kind": "PROJECT_MEMORY_BOOTSTRAP_MANIFEST",
                "scope": project_id,
            }
            auth_ref = {
                "sha256": auth_sha,
                "locator": str(Path(authorization_path).expanduser().absolute()),
                "kind": "PROJECT_MEMORY_BOOTSTRAP_AUTHORIZATION",
                "scope": project_id,
            }
            event = memory.append_event(
                stream="operational.bootstrap",
                event_type="PROJECT_MEMORY_BOOTSTRAPPED",
                subject_id=project_id,
                actor_type=authorization["authority_class"],
                actor_id=authorization["authority_id"],
                payload={
                    "manifest_file_sha256": manifest_sha,
                    "authorization_file_sha256": auth_sha,
                    "claim_count": len(manifest["claims"]),
                    "proposed_decision_count": len(manifest["proposed_decisions"]),
                    "accepted_truth_modified": False,
                },
                evidence_refs=[manifest_ref, auth_ref],
                occurred_at=authorization["bootstrap_recorded_at"],
                recorded_at=authorization["bootstrap_recorded_at"],
            )
            verification = memory.verify()
            if verification.get("ok") is not True:
                raise RuntimeError("bootstrap OperationalMemory verification failed: " + "; ".join(verification.get("errors") or []))
            projection = memory.projection()
            memory.con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        wal = Path(str(temp) + "-wal")
        if wal.exists() and wal.stat().st_size:
            raise RuntimeError("temporary WAL still contains uncheckpointed bytes")
        if target.exists() or target.is_symlink():
            raise FileExistsError("target appeared before atomic publish")
        # Atomic no-clobber publication on the same filesystem. os.link fails if target exists.
        os.link(temp, target, follow_symlinks=False)
        temp.unlink()
        for sidecar in (Path(str(temp) + "-wal"), Path(str(temp) + "-shm")):
            if sidecar.exists():
                sidecar.unlink()
        with OperationalMemory(str(target), read_only=True) as memory:
            after_verify = memory.verify()
            if after_verify.get("ok") is not True:
                raise RuntimeError("published OperationalMemory verification failed")
            after_projection = memory.projection()
            prior = _bootstrap_event(memory, project_id=project_id, manifest_sha=manifest_sha, auth_sha=auth_sha)
            if prior is None:
                raise RuntimeError("published bootstrap receipt event missing")
        return _receipt(
            "PROJECT_MEMORY_BOOTSTRAP_PASS",
            "VERIFIED_PROJECT_MEMORY_PUBLISHED",
            project_id=project_id,
            target_db=str(target),
            wrote=True,
            manifest_file_sha256=manifest_sha,
            authorization_file_sha256=auth_sha,
            authority={
                "class": authorization["authority_class"],
                "id": authorization["authority_id"],
                "ref": authorization["authority_ref"],
            },
            evidence=verified_evidence,
            claims_created=len(manifest["claims"]),
            proposed_decisions_created=len(manifest["proposed_decisions"]),
            bootstrap_event=prior,
            projection={
                "projection_sha256": after_projection.get("projection_sha256"),
                "event_cursor": after_projection.get("event_cursor"),
                "event_chain_head": after_projection.get("event_chain_head"),
                "valid_at": after_projection.get("valid_at"),
            },
            publication="TEMP_DB_VERIFY_THEN_ATOMIC_LINK_NO_CLOBBER",
        )
    except Exception as exc:
        _cleanup_temp(temp)
        # If the target was linked but post-publication verification failed, remove only
        # the target we just created. It could not have existed before os.link.
        try:
            if target.exists() and target.is_file():
                with OperationalMemory(str(target), read_only=True) as memory:
                    prior = _bootstrap_event(memory, project_id=project_id, manifest_sha=manifest_sha, auth_sha=auth_sha)
                if prior is not None:
                    target.unlink()
        except Exception:
            pass
        return _receipt(
            "PROJECT_MEMORY_BOOTSTRAP_REVISE",
            "BOOTSTRAP_PUBLISH_ROLLED_BACK",
            project_id=project_id,
            target_db=str(target),
            errors=[f"{type(exc).__name__}: {exc}"],
        )
