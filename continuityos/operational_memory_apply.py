"""Atomic, separately-authorized apply gate for OperationalMemory delta proposals.

R36 proposal generation is current-session/read-only. Applying a proposal is a
separate effectful operation and is therefore *forbidden* whenever any current
session binding is declared. In legacy/unbound mode this module still requires one
exact authorization artifact, exact proposal-file SHA-256, exact current projection
identity, and exact superseded-record hashes.

All claim/decision rows plus the durable MEMORY_DELTA_APPLIED event are committed in
one SQLite BEGIN IMMEDIATE transaction. Any validation or integrity failure rolls
back the whole delta.

This applies only to the shadow Common Operational Memory. It never changes Control
Center accepted truth, canonical R64 state, deployment state, trading permissions,
or capital permissions.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Sequence

from .current_effect_boundary import (
    MODE_LEGACY,
    CurrentEffectBoundaryError,
    assert_current_effect_allowed,
    inspect_current_session,
)
from .current_memory_delta import PROPOSAL_SCHEMA
from .current_work import build_current_work_from_db
from .operational_memory import (
    DECISION_STATES,
    EVIDENCE_STATES,
    IdentityConflict,
    OperationalMemory,
    PolicyViolation,
    _canonical_json,
    _nonempty,
    _normalize_time,
    _sha256_text,
    normalize_evidence_refs,
    strict_json_loads,
)

AUTH_SCHEMA = "continuityos.operational_memory.apply_authorization/v1"
RECEIPT_SCHEMA = "continuityos.operational_memory.apply_receipt/v1"
AUTH_DECISION = "APPROVE_SHADOW_MEMORY_APPLY"
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
TERMINAL_DECISIONS = {"ACCEPTED", "REJECTED", "HOLD", "SUPERSEDED"}
PROPOSAL_BODY_KEYS = {
    "schema", "terminal", "reason", "project_id", "request_sha256", "base",
    "operations", "rationale", "requirements", "apply_status",
    "apply_implemented", "execution_decision", "execution_authorized", "effects",
}
PROPOSAL_ALLOWED_KEYS = PROPOSAL_BODY_KEYS | {
    "proposal_id", "operational_memory", "current_session", "request_input"
}


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


def _result(
    terminal: str,
    reason: str,
    *,
    project_id: str | None = None,
    proposal_id: str | None = None,
    errors: Sequence[str] | None = None,
    wrote: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "terminal": terminal,
        "reason": reason,
        "project_id": project_id,
        "proposal_id": proposal_id,
        "errors": list(errors or []),
        "shadow_memory_apply": "APPLIED" if wrote else "NOT_APPLIED",
        "accepted_truth_modified": False,
        "execution_authorized": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "effects": _effects(wrote=wrote),
        **extra,
    }


def _stable_read(path: Path, label: str) -> bytes:
    path = Path(path).expanduser().absolute()
    if path.is_symlink():
        raise ValueError(f"{label}: symlink refused")
    try:
        before = path.stat()
    except OSError as exc:
        raise ValueError(f"{label}: missing") from exc
    attrs = getattr(before, "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise ValueError(f"{label}: reparse point refused")
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label}: not a regular file")
    if before.st_size > MAX_ARTIFACT_BYTES:
        raise ValueError(f"{label}: too large")
    first = path.read_bytes()
    middle = path.stat()
    second = path.read_bytes()
    after = path.stat()
    identities = {
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
        (middle.st_dev, middle.st_ino, middle.st_size, middle.st_mtime_ns),
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
    }
    if len(identities) != 1 or first != second or len(first) != before.st_size:
        raise ValueError(f"{label}: changed during read")
    return first


def _load_json_bytes(payload: bytes, label: str) -> Mapping[str, Any]:
    try:
        text = payload.decode("utf-8-sig")
        value = strict_json_loads(text)
    except Exception as exc:
        raise ValueError(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"{label}: root must be an object")
    return value


def _require_sha(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not SHA_RE.fullmatch(text):
        raise ValueError(f"{label}: invalid SHA-256")
    return text


def _validate_proposal(value: Mapping[str, Any]) -> dict[str, Any]:
    extra = set(value) - PROPOSAL_ALLOWED_KEYS
    missing = PROPOSAL_BODY_KEYS | {"proposal_id"} - set(value)
    if extra or missing:
        raise ValueError(f"proposal keys mismatch: missing={sorted(missing)} extra={sorted(extra)}")
    if value.get("schema") != PROPOSAL_SCHEMA:
        raise ValueError("proposal schema mismatch")
    if value.get("terminal") != "CURRENT_MEMORY_DELTA_PROPOSAL_PASS":
        raise ValueError("proposal is not PASS")
    if value.get("apply_status") != "NOT_APPLIED" or value.get("apply_implemented") is not False:
        raise ValueError("proposal apply ceiling mismatch")
    if value.get("execution_authorized") is not False:
        raise ValueError("proposal unexpectedly authorizes execution")
    body = {key: value[key] for key in PROPOSAL_BODY_KEYS}
    expected_id = "omdp-" + _sha256_text(_canonical_json(body))[:40]
    if value.get("proposal_id") != expected_id:
        raise ValueError("proposal_id integrity mismatch")
    project_id = _nonempty(value.get("project_id"), field="project_id")
    operations = value.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= 64:
        raise ValueError("proposal operations must contain 1..64 rows")
    for index, operation in enumerate(operations):
        if not isinstance(operation, Mapping):
            raise ValueError(f"operations[{index}] is not an object")
        if operation.get("operation_index") != index:
            raise ValueError(f"operations[{index}] index mismatch")
        if operation.get("subject_id") != project_id:
            raise ValueError(f"operations[{index}] project mismatch")
        if operation.get("op") not in {
            "RECORD_CLAIM", "SUPERSEDE_CLAIM", "RECORD_DECISION", "SUPERSEDE_DECISION"
        }:
            raise ValueError(f"operations[{index}] unsupported op")
    base = value.get("base")
    if not isinstance(base, Mapping):
        raise ValueError("proposal base missing")
    _require_sha(base.get("projection_sha256"), "base.projection_sha256")
    _require_sha(base.get("event_chain_head"), "base.event_chain_head")
    _require_sha(base.get("current_work_capsule_sha256"), "base.current_work_capsule_sha256")
    if not isinstance(base.get("event_cursor"), int) or isinstance(base.get("event_cursor"), bool) or base["event_cursor"] < 0:
        raise ValueError("base.event_cursor invalid")
    return dict(value)


def _validate_authorization(
    value: Mapping[str, Any],
    *,
    proposal: Mapping[str, Any],
    proposal_file_sha256: str,
) -> dict[str, Any]:
    expected = {
        "schema", "decision", "proposal_id", "proposal_file_sha256", "project_id",
        "base_projection_sha256", "base_event_cursor", "base_event_chain_head",
        "operation_count", "authority_class", "authority_id", "authority_ref",
        "apply_recorded_at", "rationale",
    }
    if set(value) != expected:
        raise ValueError(
            f"authorization keys mismatch: missing={sorted(expected - set(value))} extra={sorted(set(value) - expected)}"
        )
    if value.get("schema") != AUTH_SCHEMA or value.get("decision") != AUTH_DECISION:
        raise ValueError("authorization identity mismatch")
    if value.get("proposal_id") != proposal.get("proposal_id"):
        raise ValueError("authorization proposal_id mismatch")
    if _require_sha(value.get("proposal_file_sha256"), "proposal_file_sha256") != proposal_file_sha256:
        raise ValueError("authorization proposal file SHA mismatch")
    if value.get("project_id") != proposal.get("project_id"):
        raise ValueError("authorization project mismatch")
    base = proposal["base"]
    if _require_sha(value.get("base_projection_sha256"), "base_projection_sha256") != base.get("projection_sha256"):
        raise ValueError("authorization base projection mismatch")
    if value.get("base_event_cursor") != base.get("event_cursor"):
        raise ValueError("authorization base cursor mismatch")
    if _require_sha(value.get("base_event_chain_head"), "base_event_chain_head") != base.get("event_chain_head"):
        raise ValueError("authorization base chain-head mismatch")
    if value.get("operation_count") != len(proposal["operations"]):
        raise ValueError("authorization operation_count mismatch")
    authority_class = _nonempty(value.get("authority_class"), field="authority_class").upper()
    if authority_class not in {"HUMAN", "DETERMINISTIC_CONTROLLER"}:
        raise ValueError("apply authorization requires HUMAN or DETERMINISTIC_CONTROLLER")
    authority_id = _nonempty(value.get("authority_id"), field="authority_id")
    authority_ref = _nonempty(value.get("authority_ref"), field="authority_ref")
    apply_time = _normalize_time(_nonempty(value.get("apply_recorded_at"), field="apply_recorded_at"), field="apply_recorded_at")
    valid_at = proposal["base"].get("valid_at")
    if isinstance(valid_at, str) and valid_at and apply_time < _normalize_time(valid_at, field="base.valid_at"):
        raise ValueError("apply_recorded_at precedes proposal base valid_at")
    rationale = _nonempty(value.get("rationale"), field="rationale")
    return {
        **dict(value),
        "authority_class": authority_class,
        "authority_id": authority_id,
        "authority_ref": authority_ref,
        "apply_recorded_at": apply_time,
        "rationale": rationale,
    }


def _base_identity(projection: Mapping[str, Any], current_work: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "projection_sha256": projection.get("projection_sha256"),
        "event_cursor": projection.get("event_cursor"),
        "event_chain_head": projection.get("event_chain_head"),
        "current_work_capsule_sha256": current_work.get("capsule_sha256"),
    }


def _expected_base(proposal: Mapping[str, Any]) -> dict[str, Any]:
    base = proposal["base"]
    return {
        "projection_sha256": base.get("projection_sha256"),
        "event_cursor": base.get("event_cursor"),
        "event_chain_head": base.get("event_chain_head"),
        "current_work_capsule_sha256": base.get("current_work_capsule_sha256"),
    }


def _find_prior_apply(memory: OperationalMemory, proposal_id: str, proposal_sha: str) -> dict[str, Any] | None:
    for row in memory.con.execute(
        "SELECT event_id,sequence,content_hash,chain_hash,payload_json FROM events WHERE event_type='MEMORY_DELTA_APPLIED' ORDER BY sequence"
    ):
        payload = strict_json_loads(row["payload_json"])
        if not isinstance(payload, Mapping) or payload.get("proposal_id") != proposal_id:
            continue
        if payload.get("proposal_file_sha256") != proposal_sha:
            raise IdentityConflict("proposal_id already applied from different proposal bytes")
        return {
            "event_id": row["event_id"],
            "sequence": int(row["sequence"]),
            "content_hash": row["content_hash"],
            "chain_hash": row["chain_hash"],
            "payload": dict(payload),
        }
    return None


def _current_claim_rows(con: Any, project_id: str, predicate: str, scope: str) -> list[Any]:
    return list(con.execute(
        """
        SELECT c.* FROM claims c
        LEFT JOIN claims n ON n.supersedes_id=c.claim_id
        WHERE c.subject_id=? AND c.predicate=? AND c.scope=? AND n.claim_id IS NULL
        ORDER BY c.recorded_at,c.claim_id
        """,
        (project_id, predicate, scope),
    ))


def _current_decision_rows(con: Any, project_id: str, decision_type: str) -> list[Any]:
    return list(con.execute(
        """
        SELECT d.* FROM decisions d
        LEFT JOIN decisions n ON n.supersedes_id=d.decision_id
        WHERE d.subject_id=? AND d.decision_type=? AND n.decision_id IS NULL
        ORDER BY d.recorded_at,d.decision_id
        """,
        (project_id, decision_type),
    ))


def _insert_claim_tx(memory: OperationalMemory, con: Any, op: Mapping[str, Any], auth: Mapping[str, Any]) -> dict[str, Any]:
    project_id = _nonempty(op.get("subject_id"), field="subject_id")
    predicate = _nonempty(op.get("predicate"), field="predicate")
    scope = _nonempty(op.get("scope"), field="scope")
    state = _nonempty(op.get("evidence_state"), field="evidence_state").upper()
    if state not in EVIDENCE_STATES:
        raise ValueError("invalid claim evidence_state")
    refs = normalize_evidence_refs(op.get("evidence_refs"))
    if state != "UNKNOWN" and not refs:
        raise PolicyViolation(f"{state} claim requires immutable evidence")
    rec = auth["apply_recorded_at"]
    vf = _normalize_time(op.get("valid_from") or rec, field="valid_from")
    vt = _normalize_time(op.get("valid_to"), field="valid_to") if op.get("valid_to") is not None else None
    if vt is not None and vt <= vf:
        raise ValueError("valid_to must be later than valid_from")
    supersedes_id = op.get("supersedes_id")
    if supersedes_id:
        target = con.execute("SELECT * FROM claims WHERE claim_id=?", (supersedes_id,)).fetchone()
        if target is None:
            raise ValueError(f"supersedes claim missing: {supersedes_id}")
        if target["claim_hash"] != op.get("superseded_hash"):
            raise IdentityConflict(f"superseded claim hash drift: {supersedes_id}")
        if (target["subject_id"], target["predicate"], target["scope"]) != (project_id, predicate, scope):
            raise PolicyViolation("supersede claim identity mismatch")
        if con.execute("SELECT 1 FROM claims WHERE supersedes_id=?", (supersedes_id,)).fetchone() is not None:
            raise PolicyViolation(f"claim already superseded: {supersedes_id}")
    else:
        current = _current_claim_rows(con, project_id, predicate, scope)
        if current:
            raise PolicyViolation(
                f"RECORD_CLAIM would create competing current claim for {predicate}/{scope}; use SUPERSEDE_CLAIM"
            )
    core = {
        "subject_id": project_id,
        "predicate": predicate,
        "value": op.get("value"),
        "scope": scope,
        "evidence_state": state,
        "valid_from": vf,
        "valid_to": vt,
        "recorded_at": rec,
        "supersedes_id": supersedes_id,
        "evidence_refs": refs,
    }
    claim_hash = _sha256_text(_canonical_json(core))
    claim_id = f"clm-{claim_hash[:32]}"
    if con.execute("SELECT 1 FROM claims WHERE claim_id=?", (claim_id,)).fetchone() is not None:
        raise IdentityConflict(f"claim_id already exists: {claim_id}")
    event = memory._append_event_tx(
        con,
        stream="operational.claims",
        event_type="CLAIM_RECORDED",
        subject_id=project_id,
        actor_type=auth["authority_class"],
        actor_id=auth["authority_id"],
        payload={"claim_id": claim_id, "claim_hash": claim_hash, "predicate": predicate, "scope": scope},
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
            claim_id, project_id, predicate, _canonical_json(op.get("value")), scope,
            state, vf, vt, rec, supersedes_id, event.identity,
            _canonical_json(refs), claim_hash,
        ),
    )
    return {
        "operation_index": op.get("operation_index"),
        "op": op.get("op"),
        "record_id": claim_id,
        "record_hash": claim_hash,
        "event_id": event.identity,
        "event_sequence": event.sequence,
        "chain_hash": event.chain_hash,
    }


def _insert_decision_tx(memory: OperationalMemory, con: Any, op: Mapping[str, Any], auth: Mapping[str, Any]) -> dict[str, Any]:
    project_id = _nonempty(op.get("subject_id"), field="subject_id")
    decision_type = _nonempty(op.get("decision_type"), field="decision_type")
    state = _nonempty(op.get("state"), field="state").upper()
    if state not in DECISION_STATES:
        raise ValueError("invalid decision state")
    if op.get("op") == "RECORD_DECISION" and state == "SUPERSEDED":
        raise PolicyViolation("RECORD_DECISION cannot create standalone SUPERSEDED state")
    refs = normalize_evidence_refs(op.get("evidence_refs"))
    if state in TERMINAL_DECISIONS and not refs:
        raise PolicyViolation(f"{state} decision requires immutable evidence")
    rationale = _nonempty(op.get("rationale"), field="rationale")
    rec = auth["apply_recorded_at"]
    supersedes_id = op.get("supersedes_id")
    if supersedes_id:
        target = con.execute("SELECT * FROM decisions WHERE decision_id=?", (supersedes_id,)).fetchone()
        if target is None:
            raise ValueError(f"supersedes decision missing: {supersedes_id}")
        if target["decision_hash"] != op.get("superseded_hash"):
            raise IdentityConflict(f"superseded decision hash drift: {supersedes_id}")
        if (target["subject_id"], target["decision_type"]) != (project_id, decision_type):
            raise PolicyViolation("supersede decision identity mismatch")
        if con.execute("SELECT 1 FROM decisions WHERE supersedes_id=?", (supersedes_id,)).fetchone() is not None:
            raise PolicyViolation(f"decision already superseded: {supersedes_id}")
    elif state in TERMINAL_DECISIONS:
        existing_terminal = [
            row for row in _current_decision_rows(con, project_id, decision_type)
            if row["state"] in TERMINAL_DECISIONS
        ]
        if existing_terminal:
            raise PolicyViolation(
                f"terminal RECORD_DECISION would compete with current terminal {decision_type}; use SUPERSEDE_DECISION"
            )
    core = {
        "subject_id": project_id,
        "decision_type": decision_type,
        "state": state,
        "value": op.get("value"),
        "rationale": rationale,
        "authority_class": auth["authority_class"],
        "authority_id": auth["authority_id"],
        "authority_ref": auth["authority_ref"],
        "recorded_at": rec,
        "supersedes_id": supersedes_id,
        "evidence_refs": refs,
    }
    decision_hash = _sha256_text(_canonical_json(core))
    decision_id = f"dec-{decision_hash[:32]}"
    if con.execute("SELECT 1 FROM decisions WHERE decision_id=?", (decision_id,)).fetchone() is not None:
        raise IdentityConflict(f"decision_id already exists: {decision_id}")
    event = memory._append_event_tx(
        con,
        stream="operational.decisions",
        event_type="DECISION_RECORDED",
        subject_id=project_id,
        actor_type=auth["authority_class"],
        actor_id=auth["authority_id"],
        payload={
            "decision_id": decision_id,
            "decision_hash": decision_hash,
            "decision_type": decision_type,
            "state": state,
            "authority_ref": auth["authority_ref"],
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
            decision_id, project_id, decision_type, state, _canonical_json(op.get("value")),
            rationale, auth["authority_class"], auth["authority_id"], auth["authority_ref"],
            rec, supersedes_id, event.identity, _canonical_json(refs), decision_hash,
        ),
    )
    return {
        "operation_index": op.get("operation_index"),
        "op": op.get("op"),
        "record_id": decision_id,
        "record_hash": decision_hash,
        "event_id": event.identity,
        "event_sequence": event.sequence,
        "chain_hash": event.chain_hash,
    }


def apply_authorized_memory_delta(
    db_path: str | Path,
    proposal_path: str | Path,
    authorization_path: str | Path,
) -> dict[str, Any]:
    """Apply one exact proposal atomically to shadow OperationalMemory only."""
    state = inspect_current_session()
    if state.get("mode") != MODE_LEGACY:
        terminal = "CURRENT_MEMORY_APPLY_HOLD" if state.get("binding_verified") else "CURRENT_MEMORY_APPLY_REVISE"
        return _result(
            terminal,
            "CURRENT_SESSION_EFFECT_FORBIDDEN",
            errors=[str(state.get("reason") or state.get("mode"))],
            current_session=state,
        )
    try:
        assert_current_effect_allowed("operational_memory.delta_apply")
    except CurrentEffectBoundaryError as exc:  # defensive against environment race
        return _result("CURRENT_MEMORY_APPLY_HOLD", "CURRENT_SESSION_EFFECT_FORBIDDEN", errors=[str(exc)])

    try:
        proposal_bytes = _stable_read(Path(proposal_path), "proposal")
        auth_bytes = _stable_read(Path(authorization_path), "authorization")
        proposal_sha = _sha_bytes(proposal_bytes)
        auth_sha = _sha_bytes(auth_bytes)
        proposal = _validate_proposal(_load_json_bytes(proposal_bytes, "proposal"))
        authorization = _validate_authorization(
            _load_json_bytes(auth_bytes, "authorization"),
            proposal=proposal,
            proposal_file_sha256=proposal_sha,
        )
    except Exception as exc:
        return _result(
            "CURRENT_MEMORY_APPLY_REVISE",
            "APPLY_ARTIFACT_INVALID",
            errors=[f"{type(exc).__name__}: {exc}"],
        )

    project_id = str(proposal["project_id"])
    proposal_id = str(proposal["proposal_id"])
    db = Path(db_path).expanduser().absolute()
    if not db.is_file():
        return _result(
            "CURRENT_MEMORY_APPLY_REVISE",
            "OPERATIONAL_MEMORY_MISSING",
            project_id=project_id,
            proposal_id=proposal_id,
            errors=[str(db)],
        )

    try:
        with OperationalMemory(str(db), read_only=True) as memory:
            verification = memory.verify()
            if verification.get("ok") is not True:
                raise ValueError("operational memory verification failed before apply")
            prior = _find_prior_apply(memory, proposal_id, proposal_sha)
            if prior is not None:
                projection = memory.projection()
                return _result(
                    "CURRENT_MEMORY_APPLY_ALREADY_APPLIED",
                    "EXACT_PROPOSAL_ALREADY_APPLIED",
                    project_id=project_id,
                    proposal_id=proposal_id,
                    proposal_file_sha256=proposal_sha,
                    authorization_file_sha256=auth_sha,
                    durable_apply_event=prior,
                    current_projection_sha256=projection.get("projection_sha256"),
                )
            projection = memory.projection()
        current_work = build_current_work_from_db(db, project_id)
        actual_base = _base_identity(projection, current_work)
        expected_base = _expected_base(proposal)
        if actual_base != expected_base:
            return _result(
                "CURRENT_MEMORY_APPLY_REVISE",
                "STALE_OPERATIONAL_MEMORY_BASE",
                project_id=project_id,
                proposal_id=proposal_id,
                errors=[f"expected={expected_base}", f"actual={actual_base}"],
            )
    except Exception as exc:
        return _result(
            "CURRENT_MEMORY_APPLY_REVISE",
            "OPERATIONAL_MEMORY_PRECHECK_FAILED",
            project_id=project_id,
            proposal_id=proposal_id,
            errors=[f"{type(exc).__name__}: {exc}"],
        )

    try:
        with OperationalMemory(str(db)) as memory:
            with memory._write_tx() as con:
                # Repeat the full logical base check after acquiring the write lock.
                locked_projection = memory.projection()
                locked_work = build_current_work_from_db(db, project_id)
                locked_base = _base_identity(locked_projection, locked_work)
                if locked_base != _expected_base(proposal):
                    raise IdentityConflict("operational memory base changed before write lock")

                results: list[dict[str, Any]] = []
                for op in proposal["operations"]:
                    if op["op"] in {"RECORD_CLAIM", "SUPERSEDE_CLAIM"}:
                        results.append(_insert_claim_tx(memory, con, op, authorization))
                    else:
                        results.append(_insert_decision_tx(memory, con, op, authorization))

                receipt_refs = [
                    {
                        "sha256": proposal_sha,
                        "locator": str(Path(proposal_path).expanduser().absolute()),
                        "kind": "OPERATIONAL_MEMORY_DELTA_PROPOSAL",
                        "scope": project_id,
                    },
                    {
                        "sha256": auth_sha,
                        "locator": str(Path(authorization_path).expanduser().absolute()),
                        "kind": "OPERATIONAL_MEMORY_APPLY_AUTHORIZATION",
                        "scope": project_id,
                    },
                ]
                apply_event = memory._append_event_tx(
                    con,
                    stream="operational.apply",
                    event_type="MEMORY_DELTA_APPLIED",
                    subject_id=project_id,
                    actor_type=authorization["authority_class"],
                    actor_id=authorization["authority_id"],
                    payload={
                        "proposal_id": proposal_id,
                        "proposal_file_sha256": proposal_sha,
                        "authorization_file_sha256": auth_sha,
                        "base": _expected_base(proposal),
                        "operation_results": results,
                        "accepted_truth_modified": False,
                        "canonical_state_modified": False,
                    },
                    evidence_refs=receipt_refs,
                    occurred_at=authorization["apply_recorded_at"],
                    recorded_at=authorization["apply_recorded_at"],
                )
                after = memory.projection()
                verify_after = memory.verify()
                if verify_after.get("ok") is not True:
                    raise RuntimeError(
                        "post-apply verification failed inside transaction: "
                        + "; ".join(verify_after.get("errors") or [])
                    )
                durable = {
                    "event_id": apply_event.identity,
                    "sequence": apply_event.sequence,
                    "content_hash": apply_event.content_hash,
                    "chain_hash": apply_event.chain_hash,
                }
            # transaction committed here; durable apply event and operation rows share it.
        return _result(
            "CURRENT_MEMORY_APPLY_PASS",
            "AUTHORIZED_ATOMIC_SHADOW_MEMORY_DELTA_APPLIED",
            project_id=project_id,
            proposal_id=proposal_id,
            wrote=True,
            proposal_file_sha256=proposal_sha,
            authorization_file_sha256=auth_sha,
            authority={
                "class": authorization["authority_class"],
                "id": authorization["authority_id"],
                "ref": authorization["authority_ref"],
            },
            base_before=_expected_base(proposal),
            projection_after={
                "projection_sha256": after.get("projection_sha256"),
                "event_cursor": after.get("event_cursor"),
                "event_chain_head": after.get("event_chain_head"),
            },
            operation_results=results,
            durable_apply_event=durable,
            transaction="BEGIN_IMMEDIATE_ATOMIC_COMMIT",
        )
    except Exception as exc:
        return _result(
            "CURRENT_MEMORY_APPLY_REVISE",
            "ATOMIC_SHADOW_MEMORY_APPLY_ROLLED_BACK",
            project_id=project_id,
            proposal_id=proposal_id,
            proposal_file_sha256=proposal_sha,
            authorization_file_sha256=auth_sha,
            errors=[f"{type(exc).__name__}: {exc}"],
            transaction="ROLLED_BACK",
        )
