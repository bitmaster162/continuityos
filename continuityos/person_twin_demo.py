"""Synthetic Person/R21H continuity through three finite, isolated children.

The caller owns PREPARE, A and B directly. Only PREPARE writes the fixture;
both model workers read the same bytes and construct fresh synthetic host
bindings. This is a product proof, not a vault, real model run or owner grant.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Mapping, Sequence

from .current_effect_boundary import assert_current_effect_allowed

SCHEMA = "continuityos.product_demo_person_continuity/v1"
FIXTURE_SCHEMA = "continuityos.product_demo_person_continuity_fixture/v1"
WORKER_SCHEMA = "continuityos.product_demo_person_continuity_worker/v1"
PREPARE_SCHEMA = "continuityos.product_demo_person_continuity_prepare/v1"
WORK_ORDER = "COS_DEMO_PERSON_CONTINUITY_R1"
PASS = "COS_DEMO_PERSON_CONTINUITY_PASS"
HOLD = "COS_DEMO_PERSON_CONTINUITY_HOLD"
NAMESPACE = "synthetic-person-context"
QUERY = "Continue the current synthetic project context."
AT = "2026-08-25T12:50:00Z"  # Declared fixture clock, not trusted current time.
PURPOSE = "person-memory"
ROOT_PREFIX = "continuityos-person-demo-"
MAX_FIXTURE_BYTES = 131072
MAX_DB_BYTES = 2097152
MAX_OUTPUT_BYTES = 65536
OLD_TEXT = "OLD_DECISION_SENTINEL: use the retired prototype."
FOREIGN_TEXT = "FOREIGN_PRIVATE_SENTINEL: another person's context."
_socket_events: list[str] = []
_socket_guard_installed = False
WORKER_CHECKS = frozenset({"current_evidence_delivered", "old_and_foreign_excluded", "exact_query",
    "query_only", "fresh_prompt_revalidation", "one_generation", "transport", "execute_denied",
    "no_socket_events", "fixture_and_db_unchanged"})
PERSON_RECEIPT_KEYS = frozenset({"schema", "decision", "action", "evidence_count", "memory_refs",
    "prompt_boundary_revalidated", "production_admission_status", "execution_authority", "can_execute",
    "can_trade", "capital_permission", "intent_sha256", "r4_receipt_hash", "evidence_sha256", "receipt_hash"})


class PersonDemoHold(ValueError):
    """Only fixed public reason codes are raised by fixture helpers."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash(value: Any) -> str:
    return _sha(_canonical(value))


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PersonDemoHold("DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def _decode(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError()
        # JSON's finite syntax can still overflow a float (for example 1e999).
        _canonical(value)
        return value
    except Exception:
        raise PersonDemoHold("INVALID_JSON_OBJECT") from None


def _seal(value: dict[str, Any]) -> dict[str, Any]:
    return {**value, "receipt_sha256": _hash(value)}


def _sealed(value: Any) -> bool:
    try:
        return (isinstance(value, dict) and _is_sha(value.get("receipt_sha256"))
                and _hash({k: v for k, v in value.items() if k != "receipt_sha256"})
                == value["receipt_sha256"])
    except Exception:
        return False


def _governance() -> dict[str, Any]:
    return {"production_admission_status": "NOT_PRODUCTION_ADMITTED",
            "execution_authority": "NONE", "can_execute": False,
            "can_trade": False, "capital_permission": "DENY"}


def _effects() -> dict[str, Any]:
    return {"ephemeral_filesystem_write": False, "ephemeral_memory_write": False,
            "user_memory_read": False, "user_memory_write": False,
            "client_config_write": False, "network_effect": False,
            "external_model_call": False, "subprocess_execution": False,
            "child_launches": 0, "server_started": False, "deployment": False,
            "agent_dispatch": False, "trading": False, "wallet_access": False,
            "temporary_cleanup_pass": None}


def _hold(reason: str, **details: Any) -> dict[str, Any]:
    return {"schema": SCHEMA, "work_order": WORK_ORDER, "terminal": HOLD,
            "reason": reason, "mode": "SYNTHETIC_ONLY", "effects": _effects(),
            **_governance(), **details}


def _guard() -> None:
    try:
        assert_current_effect_allowed("person.demo")
    except Exception:
        raise PersonDemoHold("CURRENT_EFFECT_HOLD") from None


def _timeout(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PersonDemoHold("INVALID_TIMEOUT")
    result = float(value)
    if not math.isfinite(result) or not 0 < result <= 20.0:
        raise PersonDemoHold("INVALID_TIMEOUT")
    return result


def _reject_link(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise PersonDemoHold("FIXTURE_LINK_FORBIDDEN")


def _owned_root(root: Path) -> Path:
    if ".." in Path(root).parts:
        raise PersonDemoHold("FIXTURE_ROOT_INVALID")
    root = Path(root).absolute()
    base = Path(tempfile.gettempdir()).resolve(strict=True)
    try:
        if not root.name.startswith(ROOT_PREFIX) or not root.is_relative_to(base):
            raise PersonDemoHold("FIXTURE_ROOT_INVALID")
        for node in (root, *root.parents):
            info = node.lstat()
            _reject_link(info)
            if not stat.S_ISDIR(info.st_mode):
                raise PersonDemoHold("FIXTURE_ROOT_INVALID")
            if node == base:
                break
        info = root.lstat()
        if hasattr(os, "getuid") and (info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise PersonDemoHold("FIXTURE_ROOT_NOT_OWNED")
        return root
    except PersonDemoHold:
        raise
    except Exception:
        raise PersonDemoHold("FIXTURE_ROOT_INVALID") from None


def _read_bytes(root: Path, name: str, maximum: int) -> bytes:
    root = _owned_root(root)
    if name not in {"fixture.json", "memory.db"}:
        raise PersonDemoHold("FIXTURE_MEMBER_INVALID")
    path = root / name
    try:
        before = path.lstat()
        _reject_link(before)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise PersonDemoHold("FIXTURE_MEMBER_INVALID")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise PersonDemoHold("FIXTURE_MEMBER_CHANGED")
            data = handle.read(maximum + 1)
        after = path.lstat()
        _reject_link(after)
        if len(data) != before.st_size or len(data) > maximum or (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise PersonDemoHold("FIXTURE_MEMBER_CHANGED")
        _owned_root(root)
        return data
    except PersonDemoHold:
        raise
    except Exception:
        raise PersonDemoHold("FIXTURE_MEMBER_UNAVAILABLE") from None


def _members(root: Path) -> None:
    root = _owned_root(root)
    if {item.name for item in root.iterdir()} != {"memory.db", "fixture.json"}:
        raise PersonDemoHold("FIXTURE_MEMBERS_CHANGED")
    for item in root.iterdir():
        _reject_link(item.lstat())


class _AdmissionFixtureStore:
    """Ephemeral R3 byte fixture, never installed as a canonical backend."""

    def __init__(self):
        self.pointer: bytes | None = None
        self.candidates: dict[str, bytes] = {}

    def read_current_pointer_bytes(self):
        return self.pointer

    def read_candidate_bytes(self, candidate_id):
        return self.candidates.get(candidate_id)

    def commit_candidate_not_current(self, candidate_id, candidate_bytes):
        from .person_twin_admission_coordinator import AdmissionStoreConflict
        if candidate_id in self.candidates and self.candidates[candidate_id] != candidate_bytes:
            raise AdmissionStoreConflict("fixture candidate conflict")
        self.candidates[candidate_id] = candidate_bytes

    def promote_current_pointer(self, *, expected_pointer_sha256, pointer_bytes):
        from .person_twin_admission_coordinator import AdmissionStoreConflict
        actual = None if self.pointer is None else _sha(self.pointer)
        if actual != expected_pointer_sha256:
            raise AdmissionStoreConflict("fixture pointer conflict")
        self.pointer = pointer_bytes


def _write_fixture(root: Path, run_id: str) -> dict[str, Any]:
    _guard()
    root = _owned_root(root)
    if re.fullmatch(r"[0-9a-f]{32}", run_id) is None or any(root.iterdir()):
        raise PersonDemoHold("FIXTURE_PREPARATION_INVALID")
    from .company_twin_ingest import normalize_envelope
    from .embed import HashingEmbedder
    from .memory import Memory
    from .person_twin_admission_contracts import (
        build_consent_revocation_ledger, build_person_twin_identity, build_source_consent_receipt,
    )
    from .person_twin_admission_coordinator import PersonTwinAdmissionCoordinator
    from .person_twin_privacy_provenance import (
        build_person_twin_provenance, canonical_person_private_scope, deterministic_source_identity_hash,
    )
    identity = build_person_twin_identity(
        tenant_id="tenant:synthetic-person-demo", subject_id="subject:" + run_id,
        owner_id="human:demo-owner", controller_id="human:demo-owner",
        controller_kind="HUMAN", ownership_epoch=1, created_at="2026-08-25T00:00:00Z",
    )
    scope = canonical_person_private_scope(identity["twin_id"])
    text = ("Goal: continue the approved synthetic project.\n"
            "Decision: keep the read-only Person/R21H evidence path.\n"
            "Constraint: synthetic data only; no external effects.\n"
            "Next step: inspect the recovered current context in session B.\n"
            "Run: " + run_id)
    source = normalize_envelope({
        "schema_version": "company-twin-source-envelope/1", "tenant_id": identity["tenant_id"],
        "connector_id": "connector:synthetic-fixture", "source_system": "synthetic_fixture",
        "source_object_type": "document", "source_object_id": "document:" + run_id,
        "revision_id": "current", "observed_at": "2026-08-25T10:01:00Z",
        "effective_at": "2026-08-25T10:00:00Z", "acl": {"visibility": "PERSONAL", "scope": scope},
        "payload": {"title": "Synthetic current context", "text": text},
        "raw_ref": "synthetic://person-demo/" + run_id, "cursor": "cursor:" + run_id,
        "actor": {"actor_id": "human:demo-owner", "actor_kind": "HUMAN", "authority_class": "OWNER"},
        "deleted": False,
    })
    consent = build_source_consent_receipt(
        identity, authorizing_principal="human:demo-owner", authorizing_principal_kind="HUMAN",
        source_system=source["source_system"], source_identity_hash=deterministic_source_identity_hash(source),
        allowed_object_types=["document"], allowed_scopes=[scope], purpose=PURPOSE,
        issued_at="2026-08-25T09:00:00Z", expires_at="2026-08-26T00:00:00Z", revoked_at=None,
        source_read_authority=False, memory_admission_authority=True,
        policy_version="synthetic-person-demo/1",
    )
    ledger = build_consent_revocation_ledger()
    record = build_person_twin_provenance(
        identity, consent, ledger, source, admission_session_id="admission:" + run_id,
        purpose=PURPOSE, at="2026-08-25T11:00:00Z",
    )
    store = _AdmissionFixtureStore()
    coordinator = PersonTwinAdmissionCoordinator(
        store, session_id=record["admission_session_id"], identity=identity, consent_receipt=consent,
        source_record=source, candidate_record=record, purpose=PURPOSE,
    )
    steps = (
        (coordinator.validate, {"revocation_ledger": ledger}, "VALIDATED"),
        (coordinator.commit_not_current, {"current_revocation_ledger": ledger}, "COMMITTED_NOT_CURRENT"),
        (coordinator.postverify, {"current_revocation_ledger": ledger}, "POSTVERIFY_PASS"),
        (coordinator.promote_current, {"current_revocation_ledger": ledger}, "CURRENT"),
    )
    admission = None
    for method, kwargs, expected in steps:
        admission = method(**kwargs, at="2026-08-25T11:40:00Z")
        if admission.get("state") != expected:
            raise PersonDemoHold("FIXTURE_ADMISSION_HOLD")
    writer = Memory(str(root / "memory.db"), embedder=HashingEmbedder())
    try:
        old_id = writer.remember(OLD_TEXT, namespace=NAMESPACE)
        writer.remember(FOREIGN_TEXT, namespace="foreign-person")
        memory_id = writer.supersede(old_id, text, namespace=NAMESPACE)
        wal = writer.store.con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if wal is None or int(wal[0]) != 0:
            raise PersonDemoHold("FIXTURE_WAL_NOT_QUIESCENT")
        mode = writer.store.con.execute("PRAGMA journal_mode=DELETE").fetchone()
        if mode is None or str(mode[0]).lower() != "delete":
            raise PersonDemoHold("FIXTURE_JOURNAL_NOT_QUIESCENT")
    finally:
        writer.store.con.close()
    db = _read_bytes(root, "memory.db", MAX_DB_BYTES)
    candidate_bytes = store.read_candidate_bytes(record["id"])
    pointer_bytes = store.read_current_pointer_bytes()
    if candidate_bytes is None or pointer_bytes is None:
        raise PersonDemoHold("FIXTURE_ADMISSION_MISSING")
    fixture = {"schema": FIXTURE_SCHEMA, "run_id": run_id,
        "memory": {"id": memory_id, "namespace": NAMESPACE, "sha256": _sha(db), "size_bytes": len(db)},
        "context": {"identity": identity, "source_record": source, "consent_receipt": consent,
            "current_revocation_ledger": ledger, "person_record": record, "admission_receipt": admission,
            "current_pointer": _decode(pointer_bytes)},
        "admission_bytes": {"candidate_utf8": candidate_bytes.decode("utf-8"),
            "pointer_utf8": pointer_bytes.decode("utf-8"), "candidate_sha256": _sha(candidate_bytes),
            "pointer_sha256": _sha(pointer_bytes)}}
    raw = _canonical(fixture)
    if len(raw) > MAX_FIXTURE_BYTES:
        raise PersonDemoHold("FIXTURE_TOO_LARGE")
    fd = os.open(root / "fixture.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    _read_fixture(root, _sha(raw))
    return {"fixture_sha256": _sha(raw), "db_sha256": _sha(db), "memory_id": memory_id, "run_id": run_id}


def _read_fixture(root: Path, expected_sha256: str) -> dict[str, Any]:
    _guard()
    if not _is_sha(expected_sha256):
        raise PersonDemoHold("FIXTURE_HASH_INVALID")
    _members(root)
    raw = _read_bytes(root, "fixture.json", MAX_FIXTURE_BYTES)
    if _sha(raw) != expected_sha256:
        raise PersonDemoHold("FIXTURE_HASH_MISMATCH")
    fixture = _decode(raw)
    try:
        if set(fixture) != {"schema", "run_id", "memory", "context", "admission_bytes"}:
            raise ValueError()
        if fixture["schema"] != FIXTURE_SCHEMA or _canonical(fixture) != raw:
            raise ValueError()
        if re.fullmatch(r"[0-9a-f]{32}", fixture["run_id"]) is None:
            raise ValueError()
        memory = fixture["memory"]
        if set(memory) != {"id", "namespace", "sha256", "size_bytes"} or type(memory["id"]) is not int or memory["id"] < 1:
            raise ValueError()
        if memory["namespace"] != NAMESPACE:
            raise ValueError()
        context = fixture["context"]
        if set(context) != {"identity", "source_record", "consent_receipt", "current_revocation_ledger",
                            "person_record", "admission_receipt", "current_pointer"}:
            raise ValueError()
        stored = fixture["admission_bytes"]
        if set(stored) != {"candidate_utf8", "pointer_utf8", "candidate_sha256", "pointer_sha256"}:
            raise ValueError()
        for name, value in (("candidate", context["person_record"]), ("pointer", context["current_pointer"])):
            data = stored[name + "_utf8"].encode("utf-8")
            if data != _canonical(value) or _sha(data) != stored[name + "_sha256"]:
                raise ValueError()
        if context["admission_receipt"]["state"] != "CURRENT":
            raise ValueError()
        text = context["source_record"]["payload"]["text"]
        if not isinstance(text, str) or not 0 < len(text) <= 8192 or fixture["run_id"] not in text:
            raise ValueError()
    except Exception:
        raise PersonDemoHold("FIXTURE_CONTRACT_INVALID") from None
    db = _read_bytes(root, "memory.db", MAX_DB_BYTES)
    if _sha(db) != memory["sha256"] or len(db) != memory["size_bytes"]:
        raise PersonDemoHold("FIXTURE_DB_HASH_MISMATCH")
    return fixture


class _AdmissionReadFixture:
    def __init__(self, fixture):
        self.candidate_id = fixture["context"]["person_record"]["id"]
        self.candidate = fixture["admission_bytes"]["candidate_utf8"].encode("utf-8")
        self.pointer = fixture["admission_bytes"]["pointer_utf8"].encode("utf-8")

    def read_candidate_bytes(self, candidate_id):
        return self.candidate if candidate_id == self.candidate_id else None

    def read_current_pointer_bytes(self):
        return self.pointer


class _EmptyReplayFixture:
    def read_replay_receipt_bytes(self, replay_key):
        return None


def _fresh_host_context(fixture: Mapping[str, Any], role: str) -> dict[str, Any]:
    """New local fixture host bindings; no serialized session or inherited ALLOW."""
    if role not in {"A", "B"}:
        raise PersonDemoHold("WORKER_ROLE_INVALID")
    nonce = secrets.token_hex(16)
    identity = fixture["context"]["identity"]
    scope = fixture["context"]["person_record"]["scope"]
    owner = identity["owner_id"]
    session_effects = {name: False for name in (
        "legacy_fallback", "memory_write", "ledger_write", "filesystem_write", "network_effect",
        "server_started", "subprocess_execution", "deployment", "current_state_apply", "canonical_mutation",
        "external_message", "auto_dispatch", "trading", "wallet_access", "order_execution", "can_trade")}
    session_effects.update(capital_permission="DENY", deploy_permission="DENY")
    session = {"schema": "continuityos.current_effect_boundary/v1", "mode": "CURRENT", "declared": True,
        "binding_verified": True, "reason": "EXACT_CURRENT_SESSION_VERIFIED", "authority_generation": "R64",
        "challenge_id": "synthetic-challenge:" + nonce, "challenge_sha256": _hash([nonce, "challenge"]),
        "ack_sha256": _hash([nonce, "ack"]), "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK", "effects": session_effects}
    base = {"projection_sha256": _hash([nonce, "projection"]), "event_cursor": 1,
            "event_chain_head": _hash([nonce, "chain"])}
    core = {"proposal_id": "synthetic-proposal:" + nonce, "proposal_file_sha256": _hash([nonce, "proposal"]),
            "project_id": "synthetic-person-demo", "base": base, "operation_count": 1}
    request = {"schema": "continuityos.operational_memory.apply_authorization_request/v1",
        "terminal": "CURRENT_MEMORY_APPLY_AUTH_REQUEST_PASS", "authorization_granted": False,
        "execution_authorized": False, "apply_status": "NOT_APPLIED", "request_id": "omar-" + _hash(core)[:40],
        "proposal_id": core["proposal_id"], "proposal_file_sha256": core["proposal_file_sha256"],
        "project_id": core["project_id"], "expected_base": base, "operation_count": 1}
    packet_core = {key: request[key] for key in ("request_id", "project_id", "proposal_id",
                    "proposal_file_sha256", "expected_base", "operation_count")}
    packet_core.update(authorization_file_sha256=_hash([nonce, "authorization"]),
                       authorization={"class": "HUMAN", "id": owner, "ref": "synthetic://approval/" + nonce})
    preflight = {"schema": "continuityos.operational_memory.project_update_packet_preflight/v1",
        "terminal": "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY", "packet_valid": True,
        "authorization_record_valid": True, "apply_ready": True, "execution_authorized": False,
        "packet_id": "r4p-" + _hash(packet_core)[:40],
        **{k: v for k, v in packet_core.items() if k != "request_id"}}
    policy = {"schema_version": "company-twin-p2c/1", "tenant_id": identity["tenant_id"],
        "actors": [{"id": "actor:owner", "principal_id": owner, "actor_kind": "HUMAN",
                    "role": "DIRECTOR", "scopes": [scope]},
                   {"id": "actor:agent", "principal_id": "agent:demo", "actor_kind": "AGENT",
                    "role": "AGENT", "scopes": [scope], "manager_actor_id": "actor:owner"}],
        "grants": [{"id": "grant:owner", "actor_id": "actor:owner", "actions": ["READ", "DELEGATE"],
                    "scopes": [scope], "purposes": [PURPOSE]}],
        "delegations": [{"id": "delegation:demo", "grantor_actor_id": "actor:owner",
            "grantee_actor_id": "actor:agent", "actions": ["READ"], "scopes": [scope],
            "purposes": [PURPOSE], "parent_id": None, "expires_at": "2026-08-26T00:00:00Z", "revoked": False}],
        "explicit_denies": [], "revoked_delegation_ids": []}
    return {"current_session": session, "authorization_request": request, "authorization_preflight": preflight,
            "policy": policy, "principal_id": "agent:demo", "action": "READ", "requested_scope": scope,
            "requested_privacy_class": fixture["context"]["person_record"]["privacy_class"],
            "purpose": PURPOSE, "at": AT}


class _FixtureProvider:
    def __init__(self, root: Path, expected_sha256: str, host: Mapping[str, Any]):
        self.root, self.expected_sha256 = root, expected_sha256
        self.host = copy.deepcopy(dict(host))
        self.reads = 0

    def read_context(self):
        self.reads += 1
        fixture = _read_fixture(self.root, self.expected_sha256)
        return {**copy.deepcopy(fixture["context"]), **copy.deepcopy(self.host),
                "admission_store": _AdmissionReadFixture(fixture), "replay_store": _EmptyReplayFixture()}


class _RecordingModel:
    """Transport fixture only. Its zero timing values are not measured latency."""
    def __init__(self, profile, *, cold: bool):
        self.profile, self.loaded = profile, not cold
        self.instance_id = "synthetic-instance:" + profile.model
        self.calls: list[dict[str, Any]] = []
        self.events: list[str] = []

    def models(self):
        self.events.append("models")
        instances = [{"id": self.instance_id, "config": {
            "context_length": self.profile.context_length, "parallel": 1}}] if self.loaded else []
        return [{"key": self.profile.model, "loaded_instances": instances}]

    def _capture(self, kwargs, event):
        from .sovereign_twin_runtime import LocalChatResult
        self.events.append(event)
        if self.calls:
            raise PersonDemoHold("MULTIPLE_MODEL_CALLS")
        self.calls.append(dict(kwargs))
        return LocalChatResult(text="Synthetic transport captured the context.",
            model_instance_id=self.instance_id, stats={}, reasoning=None)

    def chat(self, **kwargs):
        return self._capture(kwargs, "chat")

    def chat_fast_streaming_jit_reconciled(self, **kwargs):
        result = self._capture(kwargs, "stream")
        self.loaded = True
        kwargs["on_model_load_end"](self.instance_id, 0.0)
        return result, {"model_instance_id": self.instance_id, "model_load_time_seconds": 0.0,
            "model_load_end_seen": True, "acquisition_signal": "model_load.end",
            "acquisition_event_type": "model_load.end",
            "event_types": ("chat.start", "model_load.end", "message.delta", "chat.end")}

    def embed(self, *args, **kwargs):
        self.events.append("embed")
        raise PersonDemoHold("UNEXPECTED_EMBEDDING")


def _audit_state() -> dict[str, Any]:
    return {"installed": _socket_guard_installed, "events": len(_socket_events), "policy": "DENY_SOCKET_EVENTS"}


def _source_sha256() -> str:
    return _sha(Path(__file__).read_bytes())


def _context_fields(text: str) -> dict[str, str]:
    labels = {"Goal": "goal", "Decision": "decision", "Constraint": "constraint", "Next step": "next_action"}
    result = {}
    for line in text.splitlines():
        label, sep, value = line.partition(": ")
        if sep and label in labels:
            if labels[label] in result:
                raise PersonDemoHold("RECOVERED_CONTEXT_INVALID")
            result[labels[label]] = value
    if set(result) != set(labels.values()) or not all(result.values()):
        raise PersonDemoHold("RECOVERED_CONTEXT_INVALID")
    return result


def _worker(root: Path, expected_sha256: str, role: str) -> tuple[dict[str, Any], int]:
    client = runtime = None
    started = time.monotonic()
    try:
        _guard()
        fixture = _read_fixture(root, expected_sha256)
        host = _fresh_host_context(fixture, role)
        from .person_twin_authority_replay import evaluate_person_twin_authority_replay
        from .person_twin_r21h_evidence import PersonReadIntent, PersonTwinR21HEvidenceAdapter
        from .sovereign_twin_runtime import DEFAULT_PROFILES, SovereignTwinRuntime
        context = fixture["context"]
        intent = PersonReadIntent(
            query_sha256=_sha(QUERY.encode("utf-8")), current_session_sha256=_hash(host["current_session"]),
            request_id=host["authorization_request"]["request_id"], packet_id=host["authorization_preflight"]["packet_id"],
            memory_id=fixture["memory"]["id"], namespace=NAMESPACE,
            person_record_id=context["person_record"]["id"], source_record_id=context["source_record"]["id"],
            principal_id=host["principal_id"], scope=host["requested_scope"],
            privacy_class=host["requested_privacy_class"], purpose=PURPOSE,
        )
        provider = _FixtureProvider(root, expected_sha256, host)
        profile = replace(DEFAULT_PROFILES["fast"], model="synthetic-person-" + role)
        client = _RecordingModel(profile, cold=role == "B")
        _read_fixture(root, expected_sha256)  # No-follow/hash checks directly before Memory opens.
        runtime = SovereignTwinRuntime(str(root / "memory.db"), client=client,
            profiles={**DEFAULT_PROFILES, "fast": profile},
            person_evidence_adapter=PersonTwinR21HEvidenceAdapter(intent, provider))
        query_only = runtime.memory.store.con.execute("PRAGMA query_only").fetchone()[0] == 1
        answer = runtime.ask(QUERY)
        denied = evaluate_person_twin_authority_replay(**{**provider.read_context(), "action": "EXECUTE"})
        if len(client.calls) != 1:
            raise PersonDemoHold("MODEL_CALL_COUNT_MISMATCH")
        prompt = client.calls[0]["system_prompt"]
        rows = json.loads(prompt.split("MEMORY_EVIDENCE_JSON:\n", 1)[1])
        delivered = [{k: row[k] for k in ("ref", "namespace", "text")} for row in rows]
        expected = [{"ref": "mem:" + str(fixture["memory"]["id"]), "namespace": NAMESPACE,
                     "text": context["source_record"]["payload"]["text"]}]
        person = dict(answer.stats["person_evidence"])
        checks = {"current_evidence_delivered": delivered == expected,
            "old_and_foreign_excluded": OLD_TEXT not in prompt and FOREIGN_TEXT not in prompt,
            "exact_query": client.calls[0]["input_text"] == QUERY, "query_only": query_only,
            "fresh_prompt_revalidation": provider.reads >= 2 and person.get("prompt_boundary_revalidated") is True,
            "one_generation": len(client.calls) == 1,
            "transport": (client.events.count("chat"), client.events.count("stream")) == ((1, 0) if role == "A" else (0, 1)),
            "execute_denied": denied.get("decision") == "DENY" and denied.get("execution_authorized") is False,
            "no_socket_events": not _socket_events}
        runtime.close()
        runtime = None
        after = _read_fixture(root, expected_sha256)
        checks["fixture_and_db_unchanged"] = after == fixture
        if not all(checks.values()):
            raise PersonDemoHold("WORKER_PROOF_MISMATCH")
        value = {"schema": WORKER_SCHEMA, "terminal": "PERSON_DEMO_WORKER_PASS", "role": role,
            "process_id": os.getpid(), "model_profile": profile.model,
            "model_calls": len(client.calls), "model_events": client.events,
            "transport": "warm_chat" if role == "A" else "cold_streaming",
            "captured_evidence": delivered, "prompt_sha256": _sha(prompt.encode("utf-8")),
            "recovered": _context_fields(delivered[0]["text"]), "session_sha256": _hash(host["current_session"]),
            "request_sha256": _hash(host["authorization_request"]),
            "packet_sha256": _hash(host["authorization_preflight"]),
            "person_evidence": person, "context_reads": provider.reads, "checks": checks,
            "fixture_sha256": expected_sha256, "db_sha256": fixture["memory"]["sha256"],
            "unsupported_execute": {"decision": denied["decision"], "reason": denied.get("reason"),
                                    "execution_authorized": denied.get("execution_authorized")},
            "socket_audit": _audit_state(), "synthetic_host_bindings": True, "fixture_clock_at": AT,
            "source_sha256": _source_sha256(),
            "duration_seconds": time.monotonic() - started, **_governance()}
        return _seal(value), 0
    except Exception as exc:
        reason = str(exc) if type(exc) is PersonDemoHold else "WORKER_VALIDATION_HOLD"
        return _seal({"schema": WORKER_SCHEMA, "terminal": "PERSON_DEMO_WORKER_HOLD", "reason": reason,
            "role": role, "process_id": os.getpid(), "model_calls": len(client.calls) if client else 0,
            "model_events": list(client.events) if client else [], "socket_audit": _audit_state(),
            **_governance()}), 2
    finally:
        if runtime is not None:
            try:
                runtime.close()
            except Exception:
                pass  # The failed normal close already produces a HOLD above.


def _run_process(command: list[str], timeout: float) -> dict[str, Any]:
    """Bound both pipes during execution, terminate and reap this owned child."""
    start = time.monotonic()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()
    child = None
    readers: list[threading.Thread] = []
    result: dict[str, Any] = {"started": False, "returncode": None, "timed_out": False,
        "output_limit_exceeded": False, "kill_attempted": False, "direct_child_reaped": False}
    try:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result.update(started=True, process_id=child.pid)
        def drain(name, pipe):
            try:
                while True:
                    chunk = pipe.read(4096)
                    if not chunk:
                        break
                    remaining = MAX_OUTPUT_BYTES - len(buffers[name])
                    buffers[name].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow.set()
                        break
            except Exception:
                overflow.set()
            finally:
                pipe.close()
        for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
            thread = threading.Thread(target=drain, args=(name, pipe), daemon=True)
            readers.append(thread)
            thread.start()
        while child.poll() is None and not overflow.is_set():
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0:
                result["timed_out"] = True
                break
            try:
                child.wait(timeout=min(remaining, 0.05))
            except subprocess.TimeoutExpired:
                pass
        if child.poll() is None:
            result["kill_attempted"] = True
            child.kill()
        child.wait(timeout=2.0)
        result["direct_child_reaped"] = True
    except Exception:
        result["reason"] = "CHILD_PROCESS_HOLD"
    finally:
        if child is not None:
            if child.poll() is None:
                try:
                    result["kill_attempted"] = True
                    child.kill()
                    child.wait(timeout=2.0)
                except Exception:
                    pass
            result["returncode"] = child.poll()
            result["direct_child_reaped"] = result["returncode"] is not None
        for reader in readers:
            reader.join(timeout=1.0)
        if any(reader.is_alive() for reader in readers):
            overflow.set()
        result.update(output_limit_exceeded=overflow.is_set(), stdout=bytes(buffers["stdout"]),
                      stderr=bytes(buffers["stderr"]), duration_seconds=time.monotonic() - start)
    return result


def _child_result(command: list[str], timeout: float) -> dict[str, Any]:
    result = _run_process(command, timeout)
    stdout = result.pop("stdout", b"")
    stderr = result.pop("stderr", b"")
    result.update(stdout_sha256=_sha(stdout), stderr_sha256=_sha(stderr), command_sha256=_hash(command))
    receipt = None
    try:
        receipt = _decode(stdout)
    except PersonDemoHold:
        pass
    result["receipt"] = receipt
    result["ok"] = (result.get("returncode") == 0 and result.get("direct_child_reaped") is True
                    and not result.get("timed_out") and not result.get("output_limit_exceeded")
                    and _sealed(receipt))
    return result


def _run_prepare(root: Path, run_id: str, timeout: float) -> dict[str, Any]:
    return _child_result(_child_command("_prepare", "--root", str(root), "--run-id", run_id), timeout)


def _run_worker(root: Path, expected_sha256: str, role: str, timeout: float) -> dict[str, Any]:
    return _child_result(_child_command("_worker", "--root", str(root),
                         "--fixture-sha256", expected_sha256, "--role", role), timeout)


def _child_command(*arguments: str) -> list[str]:
    # -I removes CWD/PYTHONPATH ambiguity; -B avoids ignored environment settings
    # producing bytecode. Current-session environment bindings remain intact.
    bootstrap = (
        "import hashlib,pathlib,runpy,sys; "
        "root=sys.argv.pop(1); expected=sys.argv.pop(1); "
        "source=pathlib.Path(root)/'continuityos'/'person_twin_demo.py'; "
        "actual=hashlib.sha256(source.read_bytes()).hexdigest(); "
        "sys.exit(2) if actual != expected else None; "
        "sys.path.insert(0,root); "
        "runpy.run_module('continuityos.person_twin_demo',run_name='__main__')"
    )
    return [sys.executable, "-I", "-B", "-c", bootstrap,
            str(Path(__file__).resolve().parent.parent), _source_sha256(), *arguments]


def _valid_worker(result: Mapping[str, Any], role: str, fixture: Mapping[str, Any], fixture_sha: str) -> bool:
    try:
        receipt = result["receipt"]
        person = receipt["person_evidence"]
        expected_evidence = [{"ref": "mem:" + str(fixture["memory"]["id"]),
            "namespace": NAMESPACE, "text": fixture["context"]["source_record"]["payload"]["text"]}]
        events = receipt["model_events"]
        return (result.get("ok") is True and result.get("direct_child_reaped") is True and _sealed(receipt)
            and receipt["schema"] == WORKER_SCHEMA and receipt["terminal"] == "PERSON_DEMO_WORKER_PASS"
            and receipt["role"] == role and receipt["model_profile"] == "synthetic-person-" + role
            and receipt["model_calls"] == 1 and type(receipt["process_id"]) is int
            and receipt["process_id"] == result["process_id"]
            and receipt["source_sha256"] == _source_sha256()
            and receipt["fixture_sha256"] == fixture_sha and receipt["db_sha256"] == fixture["memory"]["sha256"]
            and receipt["captured_evidence"] == expected_evidence
            and receipt["recovered"] == _context_fields(expected_evidence[0]["text"])
            and receipt["transport"] == ("warm_chat" if role == "A" else "cold_streaming")
            and isinstance(events, list) and set(events) <= {"models", "chat", "stream"}
            and (events.count("chat"), events.count("stream")) == ((1, 0) if role == "A" else (0, 1))
            and receipt["socket_audit"]["installed"] is True and receipt["socket_audit"]["events"] == 0
            and set(receipt["checks"]) == WORKER_CHECKS and all(v is True for v in receipt["checks"].values())
            and type(receipt["context_reads"]) is int and receipt["context_reads"] >= 2
            and set(person) == PERSON_RECEIPT_KEYS
            and person["receipt_hash"] == _hash({k: v for k, v in person.items() if k != "receipt_hash"})
            and person["schema"] == "continuityos.person-twin.r21h-evidence/v1"
            and person["decision"] == "ALLOW" and person["action"] == "READ"
            and person["evidence_count"] == 1 and person["memory_refs"] == [expected_evidence[0]["ref"]]
            and person["prompt_boundary_revalidated"] is True
            and all(person.get(k) == v and receipt.get(k) == v for k, v in _governance().items())
            and receipt["unsupported_execute"]["decision"] == "DENY"
            and receipt["unsupported_execute"]["execution_authorized"] is False
            and all(_is_sha(person[key]) for key in ("intent_sha256", "r4_receipt_hash", "evidence_sha256", "receipt_hash"))
            and all(_is_sha(receipt[key]) for key in ("session_sha256", "request_sha256", "packet_sha256", "prompt_sha256")))
    except (KeyError, TypeError, ValueError):
        return False


def _controller(*, timeout: float = 20.0) -> tuple[dict[str, Any], int]:
    """Caller-side orchestrator; all three audited children are direct siblings."""
    root = None
    root_identity = None
    children: list[dict[str, Any]] = []
    effects = _effects()
    value: dict[str, Any] = _hold("DEMO_NOT_STARTED")
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        _guard()
        timeout = _timeout(timeout)
        root = Path(tempfile.mkdtemp(prefix=ROOT_PREFIX))
        effects["ephemeral_filesystem_write"] = True
        info = _owned_root(root).lstat()
        root_identity = (info.st_dev, info.st_ino)
        run_id = secrets.token_hex(16)
        prepared = _run_prepare(root, run_id, timeout)
        children.append(prepared)
        if prepared.get("started") is True:
            effects["ephemeral_memory_write"] = "UNKNOWN"
        if not prepared.get("ok") or not isinstance(prepared.get("receipt"), dict):
            raise PersonDemoHold("FIXTURE_PREPARATION_FAILED")
        preparation = prepared["receipt"]
        if (preparation.get("schema") != PREPARE_SCHEMA or preparation.get("terminal") != "PERSON_DEMO_PREPARE_PASS"
                or preparation.get("run_id") != run_id or preparation.get("process_id") != prepared.get("process_id")):
            raise PersonDemoHold("FIXTURE_PREPARATION_RECEIPT_INVALID")
        if preparation.get("source_sha256") != _source_sha256():
            raise PersonDemoHold("FIXTURE_PREPARATION_SOURCE_MISMATCH")
        if preparation.get("socket_audit") != {"installed": True, "events": 0, "policy": "DENY_SOCKET_EVENTS"}:
            raise PersonDemoHold("FIXTURE_PREPARATION_AUDIT_INVALID")
        fixture_sha = preparation["fixture_sha256"]
        fixture = _read_fixture(root, fixture_sha)
        effects["ephemeral_memory_write"] = True
        sessions = {}
        for role in ("A", "B"):
            result = _run_worker(root, fixture_sha, role, timeout)
            children.append(result)
            if not _valid_worker(result, role, fixture, fixture_sha):
                raise PersonDemoHold("WORKER_RESULT_INVALID")
            sessions[role] = result["receipt"]
            if _read_fixture(root, fixture_sha) != fixture:
                raise PersonDemoHold("FIXTURE_CHANGED_AFTER_WORKER")
        a, b = sessions["A"], sessions["B"]
        checks = {"separate_model_processes": a["process_id"] != b["process_id"] and os.getpid() not in (a["process_id"], b["process_id"]),
            "same_current_evidence": a["captured_evidence"] == b["captured_evidence"]
                and a["person_evidence"]["evidence_sha256"] == b["person_evidence"]["evidence_sha256"],
            "fresh_session": a["session_sha256"] != b["session_sha256"],
            "fresh_request_and_packet": a["request_sha256"] != b["request_sha256"] and a["packet_sha256"] != b["packet_sha256"],
            "fresh_intent_and_r4": all(a["person_evidence"][key] != b["person_evidence"][key]
                for key in ("intent_sha256", "r4_receipt_hash", "receipt_hash")),
            "warm_a_cold_b": a["transport"] == "warm_chat" and b["transport"] == "cold_streaming",
            "snapshot_bytes_unchanged": _read_fixture(root, fixture_sha) == fixture}
        if not all(checks.values()):
            raise PersonDemoHold("CROSS_PROCESS_PROOF_MISMATCH")
        value = {"schema": SCHEMA, "work_order": WORK_ORDER, "terminal": PASS,
            "reason": "SYNTHETIC_PERSON_CONTEXT_RECOVERED", "mode": "SYNTHETIC_ONLY", "run_id": run_id,
            "orchestrator_process_id": os.getpid(), "prepare": preparation, "sessions": sessions,
            "checks": checks, "recovered": b["recovered"], "fixture_clock_at": AT,
            "snapshot": {"fixture_sha256_before": fixture_sha, "fixture_sha256_after": _sha(_read_bytes(root, "fixture.json", MAX_FIXTURE_BYTES)),
                "db_sha256_before": fixture["memory"]["sha256"], "db_sha256_after": _sha(_read_bytes(root, "memory.db", MAX_DB_BYTES)),
                "memory_ref": "mem:" + str(fixture["memory"]["id"]),
                "candidate_sha256": fixture["admission_bytes"]["candidate_sha256"],
                "pointer_sha256": fixture["admission_bytes"]["pointer_sha256"]},
            "socket_audit": {"scope": "fixture_and_model_children", "audited_children": 3, "events": 0},
            "provenance": {"signed": False, "authority": "NONE", "synthetic_host_bindings": True}, **_governance()}
        value["source_sha256"] = _source_sha256()
    except Exception as exc:
        value = _hold(str(exc) if type(exc) is PersonDemoHold else "DEMO_INTERNAL_HOLD")
    finally:
        effects["subprocess_execution"] = any(item.get("started") is True for item in children)
        effects["child_launches"] = sum(item.get("started") is True for item in children)
        if root is not None:
            try:
                info = _owned_root(root).lstat()
                if root_identity != (info.st_dev, info.st_ino) or any(
                    item.get("started") and item.get("direct_child_reaped") is not True for item in children):
                    raise PersonDemoHold("CLEANUP_OWNERSHIP_UNCONFIRMED")
                effects["ephemeral_memory_write"] = any(item.name == "memory.db" for item in root.iterdir())
                for item in root.iterdir():
                    _reject_link(item.lstat())
                shutil.rmtree(root)
                effects["temporary_cleanup_pass"] = not root.exists()
            except Exception:
                effects["temporary_cleanup_pass"] = False
            if effects["temporary_cleanup_pass"] is not True:
                value["terminal"], value["reason"] = HOLD, "TEMPORARY_CLEANUP_FAILED"
        else:
            effects["temporary_cleanup_pass"] = True
    value["effects"] = effects
    value["temporary_path_removed"] = effects["temporary_cleanup_pass"]
    value["processes"] = [{k: v for k, v in item.items() if k not in {"receipt", "ok"}} for item in children]
    value["started_at_utc"] = started_at
    value["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    return _seal(value), 0 if value["terminal"] == PASS else 2


def run_person_continuity(*, timeout: float = 20.0) -> tuple[dict[str, Any], int]:
    return _controller(timeout=timeout)


def render_person_continuity(value: Mapping[str, Any]) -> str:
    passed = value.get("terminal") == PASS
    lines = ["ContinuityOS Person continuity demo  " + ("PASS" if passed else "HOLD")]
    if passed:
        lines.append("Boundary      fresh A/B processes; synthetic model profiles; B cold")
        for key, label in (("goal", "Goal"), ("decision", "Decision"), ("constraint", "Constraint"), ("next_action", "Next step")):
            lines.append(f"{label:<14}{value['recovered'][key]}")
        lines.append("Memory ref    " + str(value["snapshot"]["memory_ref"]))
    else:
        lines.append("Reason        " + str(value.get("reason", "UNKNOWN")))
    lines.extend(["External AI   NOT USED", "Production    NOT_PRODUCTION_ADMITTED",
                  "Cleanup       " + ("PASS" if value.get("temporary_path_removed") is True else "HOLD")])
    return "\n".join(lines)


def _install_child_socket_guard() -> None:
    global _socket_guard_installed
    def deny(event, args):
        if event.startswith("socket."):
            _socket_events.append(event)
            raise RuntimeError("PERSON_DEMO_NETWORK_DENIED")
    sys.addaudithook(deny)
    _socket_guard_installed = True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m continuityos.person_twin_demo", add_help=False)
    parser.add_argument("operation", choices=["_prepare", "_worker"])
    parser.add_argument("--root", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--fixture-sha256")
    parser.add_argument("--role", choices=["A", "B"])
    args = parser.parse_args(argv)
    try:
        _guard()
        _install_child_socket_guard()
        if args.operation == "_prepare":
            result = _write_fixture(Path(args.root), args.run_id or "")
            value, code = _seal({"schema": PREPARE_SCHEMA, "terminal": "PERSON_DEMO_PREPARE_PASS",
                "process_id": os.getpid(), "socket_audit": _audit_state(),
                "source_sha256": _source_sha256(), **result, **_governance()}), 0
        else:
            value, code = _worker(Path(args.root), args.fixture_sha256 or "", args.role or "")
    except Exception as exc:
        value, code = _seal(_hold(str(exc) if type(exc) is PersonDemoHold else "CHILD_VALIDATION_HOLD")), 2
    print(_canonical(value).decode("utf-8"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
