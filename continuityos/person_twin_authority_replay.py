from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Protocol

from .company_twin_policy import evaluate as evaluate_policy, validate_policy
from .current_effect_boundary import MODE_CURRENT, SCHEMA as CURRENT_EFFECT_SCHEMA
from .person_twin_admission_contracts import (
    NOT_PRODUCTION_ADMITTED,
    evaluate_consent,
    validate_consent_revocation_ledger,
    validate_person_twin_identity,
    validate_source_consent_receipt,
)
from .person_twin_privacy_provenance import (
    validate_person_twin_record,
    validate_privacy_scope,
)

SCHEMA_VERSION = "continuityos.person-twin.authority-replay/v2"
ADMISSION_SCHEMA = "continuityos.person-twin.admission-coordinator/v2"
CURRENT_POINTER_SCHEMA = "continuityos.person-twin.current-pointer/v1"
AUTH_REQUEST_SCHEMA = "continuityos.operational_memory.apply_authorization_request/v1"
PREFLIGHT_SCHEMA = "continuityos.operational_memory.project_update_packet_preflight/v1"
SUPPORTED_ACTIONS = {"READ", "PROPOSE", "APPROVE"}
EXACT_CURRENT_AUTHORITY_CEILING = "NO_FURTHER_AGENT_WORK"


class PersonTwinAuthorityReplayError(ValueError):
    pass


class AdmissionReadStore(Protocol):
    """Read-only subset of the R3 admission store used to prove CURRENT."""

    def read_current_pointer_bytes(self) -> bytes | None: ...

    def read_candidate_bytes(self, candidate_id: str) -> bytes | None: ...


class DurableReplayReadStore(Protocol):
    """Read-only durable replay lookup. R4 never writes this store."""

    def read_replay_receipt_bytes(self, replay_key: str) -> bytes | None: ...


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _hash(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PersonTwinAuthorityReplayError(f"{field} must be non-empty")
    return value


def _sha(value: Any, field: str) -> str:
    value = _text(value, field)
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise PersonTwinAuthorityReplayError(f"{field} must be lowercase sha256")
    return value


def _mapping_from_canonical_bytes(payload: bytes, label: str) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload:
        raise PersonTwinAuthorityReplayError(f"{label} bytes missing")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise PersonTwinAuthorityReplayError(f"{label} bytes invalid JSON") from exc
    if not isinstance(decoded, Mapping):
        raise PersonTwinAuthorityReplayError(f"{label} root must be object")
    result = dict(decoded)
    if _canonical_bytes(result) != payload:
        raise PersonTwinAuthorityReplayError(f"{label} bytes are not canonical")
    return result


def _ceiling(value: Mapping[str, Any], label: str) -> None:
    if value.get("production_admission_status") != NOT_PRODUCTION_ADMITTED:
        raise PersonTwinAuthorityReplayError(f"{label} production admission escalation")
    if value.get("execution_authority") != "NONE" or value.get("can_execute") is not False:
        raise PersonTwinAuthorityReplayError(f"{label} execution authority escalation")
    if value.get("can_trade") not in (False, None):
        raise PersonTwinAuthorityReplayError(f"{label} trading authority escalation")
    if value.get("capital_permission") not in ("DENY", None):
        raise PersonTwinAuthorityReplayError(f"{label} capital authority escalation")


def _current_admission(
    identity: Mapping[str, Any],
    record: Mapping[str, Any],
    admission: Mapping[str, Any],
    pointer: Mapping[str, Any],
    admission_store: AdmissionReadStore,
) -> dict[str, str]:
    if admission.get("schema_version") != ADMISSION_SCHEMA or admission.get("state") != "CURRENT":
        raise PersonTwinAuthorityReplayError("admission receipt is not exact CURRENT")
    _ceiling(admission, "admission")
    session_id = _text(admission.get("session_id"), "admission.session_id")
    candidate_id = _text(admission.get("candidate_id"), "admission.candidate_id")
    candidate_sha = _sha(admission.get("candidate_sha256"), "admission.candidate_sha256")
    if session_id != record.get("admission_session_id"):
        raise PersonTwinAuthorityReplayError("admission session identity mismatch")
    expected_candidate_bytes = _canonical_bytes(record)
    if candidate_id != record.get("id") or candidate_sha != hashlib.sha256(expected_candidate_bytes).hexdigest():
        raise PersonTwinAuthorityReplayError("admission candidate identity mismatch")
    if admission.get("identity_fingerprint") != identity.get("identity_fingerprint"):
        raise PersonTwinAuthorityReplayError("admission identity fingerprint mismatch")

    try:
        stored_candidate = admission_store.read_candidate_bytes(candidate_id)
        stored_pointer = admission_store.read_current_pointer_bytes()
    except Exception as exc:
        raise PersonTwinAuthorityReplayError("admission readback failed") from exc
    if stored_candidate is None:
        raise PersonTwinAuthorityReplayError("current candidate missing from admission store")
    if stored_candidate != expected_candidate_bytes:
        raise PersonTwinAuthorityReplayError("candidate byte readback mismatch")
    if hashlib.sha256(stored_candidate).hexdigest() != candidate_sha:
        raise PersonTwinAuthorityReplayError("candidate hash readback mismatch")
    if stored_pointer is None:
        raise PersonTwinAuthorityReplayError("current pointer missing from admission store")

    stored_pointer_value = _mapping_from_canonical_bytes(stored_pointer, "current pointer")
    if _canonical_bytes(pointer) != stored_pointer:
        raise PersonTwinAuthorityReplayError("caller current pointer differs from admission readback")
    if stored_pointer_value != dict(pointer):
        raise PersonTwinAuthorityReplayError("current pointer readback mismatch")
    if stored_pointer_value.get("schema_version") != CURRENT_POINTER_SCHEMA or stored_pointer_value.get("state") != "CURRENT":
        raise PersonTwinAuthorityReplayError("current pointer is not exact CURRENT")
    _ceiling(stored_pointer_value, "current pointer")
    expected = {
        "twin_id": identity.get("twin_id"),
        "candidate_id": candidate_id,
        "candidate_sha256": candidate_sha,
        "identity_fingerprint": identity.get("identity_fingerprint"),
    }
    if any(stored_pointer_value.get(key) != val for key, val in expected.items()):
        raise PersonTwinAuthorityReplayError("current pointer identity mismatch")
    return {
        "session_id": session_id,
        "candidate_id": candidate_id,
        "candidate_sha256": candidate_sha,
        "current_pointer_hash": hashlib.sha256(stored_pointer).hexdigest(),
    }


def _current_session(value: Mapping[str, Any]) -> str:
    if value.get("schema") != CURRENT_EFFECT_SCHEMA or value.get("mode") != MODE_CURRENT:
        raise PersonTwinAuthorityReplayError("current session is not CURRENT")
    if value.get("binding_verified") is not True or value.get("session_effect_ceiling") != "READ_ONLY":
        raise PersonTwinAuthorityReplayError("current session binding/ceiling invalid")
    if value.get("authority_ceiling") != EXACT_CURRENT_AUTHORITY_CEILING:
        raise PersonTwinAuthorityReplayError("current session authority ceiling mismatch")
    effects = value.get("effects")
    if not isinstance(effects, Mapping):
        raise PersonTwinAuthorityReplayError("current session effects missing")
    denied = {
        "memory_write", "ledger_write", "filesystem_write", "network_effect",
        "server_started", "subprocess_execution", "deployment", "current_state_apply",
        "canonical_mutation", "external_message", "auto_dispatch", "trading",
        "wallet_access", "order_execution", "can_trade",
    }
    if any(effects.get(key) is not False for key in denied):
        raise PersonTwinAuthorityReplayError("current session effect ceiling widened")
    if effects.get("capital_permission") != "DENY" or effects.get("deploy_permission") != "DENY":
        raise PersonTwinAuthorityReplayError("current session deny ceiling widened")
    for field in ("authority_generation", "challenge_id"):
        _text(value.get(field), f"current_session.{field}")
    _sha(value.get("challenge_sha256"), "current_session.challenge_sha256")
    _sha(value.get("ack_sha256"), "current_session.ack_sha256")
    return _hash(dict(value))


def _authorization_chain(request: Mapping[str, Any], preflight: Mapping[str, Any]) -> dict[str, str]:
    if request.get("schema") != AUTH_REQUEST_SCHEMA or request.get("terminal") != "CURRENT_MEMORY_APPLY_AUTH_REQUEST_PASS":
        raise PersonTwinAuthorityReplayError("authorization request is not PASS")
    if request.get("authorization_granted") is not False or request.get("execution_authorized") is not False:
        raise PersonTwinAuthorityReplayError("authorization request manufactured authority")
    if request.get("apply_status") != "NOT_APPLIED":
        raise PersonTwinAuthorityReplayError("authorization request is not pre-apply")

    proposal_id = _text(request.get("proposal_id"), "request.proposal_id")
    proposal_sha = _sha(request.get("proposal_file_sha256"), "request.proposal_file_sha256")
    project_id = _text(request.get("project_id"), "request.project_id")
    count = request.get("operation_count")
    base = request.get("expected_base")
    if not isinstance(base, Mapping) or not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise PersonTwinAuthorityReplayError("authorization request base/count invalid")
    snapshot_sha = _sha(base.get("projection_sha256"), "request.base.projection_sha256")
    _sha(base.get("event_chain_head"), "request.base.event_chain_head")
    cursor = base.get("event_cursor")
    if not isinstance(cursor, int) or isinstance(cursor, bool) or cursor < 0:
        raise PersonTwinAuthorityReplayError("authorization request cursor invalid")
    request_id = _text(request.get("request_id"), "request.request_id")
    expected_request_id = "omar-" + _hash({
        "proposal_id": proposal_id,
        "proposal_file_sha256": proposal_sha,
        "project_id": project_id,
        "base": dict(base),
        "operation_count": count,
    })[:40]
    if request_id != expected_request_id:
        raise PersonTwinAuthorityReplayError("authorization request_id integrity mismatch")

    if preflight.get("schema") != PREFLIGHT_SCHEMA or preflight.get("terminal") != "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY":
        raise PersonTwinAuthorityReplayError("authorization preflight is not READY")
    required_true = ("packet_valid", "authorization_record_valid", "apply_ready")
    if any(preflight.get(key) is not True for key in required_true) or preflight.get("execution_authorized") is not False:
        raise PersonTwinAuthorityReplayError("authorization preflight failed closed")
    if preflight.get("proposal_id") != proposal_id or preflight.get("proposal_file_sha256") != proposal_sha:
        raise PersonTwinAuthorityReplayError("authorization proposal identity mismatch")
    if preflight.get("expected_base") != dict(base):
        raise PersonTwinAuthorityReplayError("authorization snapshot identity mismatch")

    auth = preflight.get("authorization")
    if not isinstance(auth, Mapping):
        raise PersonTwinAuthorityReplayError("authorization identity missing")
    auth_class = _text(auth.get("class"), "authorization.class").upper()
    if auth_class not in {"HUMAN", "DETERMINISTIC_CONTROLLER"}:
        raise PersonTwinAuthorityReplayError("authorization class invalid")
    return {
        "request_id": request_id,
        "proposal_id": proposal_id,
        "proposal_file_sha256": proposal_sha,
        "project_id": project_id,
        "packet_id": _text(preflight.get("packet_id"), "preflight.packet_id"),
        "authorization_file_sha256": _sha(preflight.get("authorization_file_sha256"), "preflight.authorization_file_sha256"),
        "authorization_class": auth_class,
        "authorization_id": _text(auth.get("id"), "authorization.id"),
        "authorization_ref": _text(auth.get("ref"), "authorization.ref"),
        "snapshot_sha256": snapshot_sha,
        "request_hash": _hash(dict(request)),
        "preflight_hash": _hash(dict(preflight)),
    }


def _actor(policy: Mapping[str, Any], actor_id: str) -> dict[str, Any]:
    actors = [row for row in policy.get("actors", []) if isinstance(row, Mapping) and row.get("id") == actor_id]
    if len(actors) != 1:
        raise PersonTwinAuthorityReplayError("policy actor binding ambiguous")
    row = actors[0]
    return {
        "actor_id": actor_id,
        "actor_kind": _text(row.get("actor_kind"), "actor.actor_kind"),
        "role": _text(row.get("role"), "actor.role"),
        "delegation_ids": sorted(
            str(d["id"])
            for d in policy.get("delegations", [])
            if isinstance(d, Mapping) and d.get("grantee_actor_id") == actor_id and d.get("id")
        ),
    }


def _stable_replay_key(binding: Mapping[str, Any]) -> str:
    return _hash({
        "tenant_id": binding["tenant_id"],
        "twin_id": binding["twin_id"],
        "person_record_id": binding["person_record_id"],
        "candidate_id": binding["candidate_id"],
        "proposal_id": binding["proposal_id"],
        "action": binding["action"],
    })


def _receipt(
    decision: str,
    reason: str,
    action: str,
    at: str,
    *,
    binding: Mapping[str, Any] | None = None,
    replay_status: str = "DENIED",
    policy_sha: str | None = None,
) -> dict[str, Any]:
    bound = dict(binding or {})
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision": decision,
        "reason": reason,
        "action": action,
        "evaluated_at": at,
        "replay_status": replay_status,
        "effect": "READ_ONLY_DECISION",
        "mutated": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "execution_authorized": False,
        "production_admission_status": NOT_PRODUCTION_ADMITTED,
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "binding": bound,
        "replay_key": bound.get("replay_key"),
        "replay_identity_hash": bound.get("replay_identity_hash"),
        "policy_receipt_sha256": policy_sha,
    }
    body["receipt_hash"] = _hash(body)
    return body


def _validate_durable(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if receipt.get("schema_version") != SCHEMA_VERSION:
        raise PersonTwinAuthorityReplayError("durable replay schema mismatch")
    if receipt.get("decision") != "ALLOW":
        raise PersonTwinAuthorityReplayError("durable replay receipt is not ALLOW")
    if receipt.get("effect") != "READ_ONLY_DECISION":
        raise PersonTwinAuthorityReplayError("durable replay effect mismatch")
    if any((
        receipt.get("mutated") is not False,
        receipt.get("current_state_apply") is not False,
        receipt.get("canonical_mutation") is not False,
        receipt.get("execution_authorized") is not False,
        receipt.get("production_admission_status") != NOT_PRODUCTION_ADMITTED,
        receipt.get("execution_authority") != "NONE",
        receipt.get("can_execute") is not False,
        receipt.get("can_trade") is not False,
        receipt.get("capital_permission") != "DENY",
        receipt.get("deploy_permission") != "DENY",
    )):
        raise PersonTwinAuthorityReplayError("durable replay authority ceiling mismatch")

    claimed_receipt_hash = _sha(receipt.get("receipt_hash"), "durable.receipt_hash")
    body = dict(receipt)
    body.pop("receipt_hash", None)
    if claimed_receipt_hash != _hash(body):
        raise PersonTwinAuthorityReplayError("durable replay receipt hash mismatch")

    binding = receipt.get("binding")
    if not isinstance(binding, Mapping):
        raise PersonTwinAuthorityReplayError("durable replay binding missing")
    binding_value = dict(binding)
    claimed_replay_hash = _sha(binding_value.get("replay_identity_hash"), "durable.binding.replay_identity_hash")
    if receipt.get("replay_identity_hash") != claimed_replay_hash:
        raise PersonTwinAuthorityReplayError("durable replay top-level identity mismatch")
    claimed_replay_key = _sha(binding_value.get("replay_key"), "durable.binding.replay_key")
    if receipt.get("replay_key") != claimed_replay_key:
        raise PersonTwinAuthorityReplayError("durable replay top-level key mismatch")
    replay_body = dict(binding_value)
    replay_body.pop("replay_identity_hash", None)
    if _hash(replay_body) != claimed_replay_hash:
        raise PersonTwinAuthorityReplayError("durable replay identity binding mismatch")
    if _stable_replay_key(binding_value) != claimed_replay_key:
        raise PersonTwinAuthorityReplayError("durable replay stable key mismatch")
    return binding_value


def _read_durable_replay(replay_store: DurableReplayReadStore, *, replay_key: str) -> dict[str, Any] | None:
    try:
        payload = replay_store.read_replay_receipt_bytes(replay_key)
    except Exception as exc:
        raise PersonTwinAuthorityReplayError("durable replay readback failed") from exc
    if payload is None:
        return None
    value = _mapping_from_canonical_bytes(payload, "durable replay receipt")
    _validate_durable(value)
    return value


def evaluate_person_twin_authority_replay(
    *,
    identity: Mapping[str, Any],
    consent_receipt: Mapping[str, Any],
    current_revocation_ledger: Mapping[str, Any],
    source_record: Mapping[str, Any],
    person_record: Mapping[str, Any],
    admission_receipt: Mapping[str, Any],
    current_pointer: Mapping[str, Any],
    admission_store: AdmissionReadStore,
    policy: Mapping[str, Any],
    principal_id: str,
    action: str,
    requested_scope: str,
    requested_privacy_class: str,
    purpose: str,
    at: str,
    current_session: Mapping[str, Any],
    authorization_request: Mapping[str, Any],
    authorization_preflight: Mapping[str, Any],
    replay_store: DurableReplayReadStore,
) -> dict[str, Any]:
    """Pure R4 Person Twin authority/replay decision. Never executes or mutates."""
    action = str(action or "").upper()
    at = str(at or "")
    try:
        validate_person_twin_identity(identity)
        validate_source_consent_receipt(identity, consent_receipt)
        validate_consent_revocation_ledger(current_revocation_ledger)
        validate_person_twin_record(
            person_record,
            identity=identity,
            consent_receipt=consent_receipt,
            source_record=source_record,
        )
        scope = _text(requested_scope, "requested_scope")
        privacy = _text(requested_privacy_class, "requested_privacy_class")
        if scope != person_record.get("scope") or privacy != person_record.get("privacy_class"):
            raise PersonTwinAuthorityReplayError("requested privacy/scope identity drift")
        validate_privacy_scope(twin_id=str(identity["twin_id"]), privacy_class=privacy, scope=scope)

        ledger_hash = _sha(current_revocation_ledger.get("ledger_hash"), "revocation_ledger.ledger_hash")
        if person_record.get("revocation_ledger_hash") != ledger_hash:
            raise PersonTwinAuthorityReplayError("current revocation ledger identity drift")
        consent = evaluate_consent(
            identity,
            consent_receipt,
            revocation_ledger=current_revocation_ledger,
            at=at,
            requested_object_type=str(source_record["source_object_type"]),
            requested_scope=scope,
            purpose=_text(purpose, "purpose"),
            require_source_read=False,
            require_memory_admission=True,
        )
        if consent.get("decision") != "ALLOW" or consent.get("revocation_ledger_hash") != ledger_hash:
            raise PersonTwinAuthorityReplayError(f"current consent denied:{consent.get('reason')}")

        admission = _current_admission(identity, person_record, admission_receipt, current_pointer, admission_store)
        session_hash = _current_session(current_session)
        auth = _authorization_chain(authorization_request, authorization_preflight)
        validate_policy(policy)
        if policy.get("tenant_id") != identity.get("tenant_id"):
            raise PersonTwinAuthorityReplayError("policy tenant identity mismatch")
        if action == "EXECUTE":
            raise PersonTwinAuthorityReplayError("EXECUTE unsupported in R4")
        if action not in SUPPORTED_ACTIONS:
            raise PersonTwinAuthorityReplayError("action outside R4 scope")

        principal = _text(principal_id, "principal_id")
        resource = {
            "id": person_record["id"],
            "tenant_id": identity["tenant_id"],
            "scope": scope,
            "source_acl_scopes": [str(source_record["source_acl"]["scope"])],
            "classification": privacy,
        }
        policy_decision = evaluate_policy(
            policy,
            principal_id=principal,
            resource=resource,
            action=action,
            context={"purpose": purpose},
            at=at,
        )
        if policy_decision.get("decision") != "ALLOW":
            raise PersonTwinAuthorityReplayError(f"policy denied:{policy_decision.get('reason')}")
        actor = _actor(policy, _text(policy_decision.get("actor_id"), "policy.actor_id"))
        if action == "APPROVE":
            if actor["actor_kind"] != "HUMAN":
                raise PersonTwinAuthorityReplayError("APPROVE requires HUMAN actor")
            if auth["authorization_class"] != "HUMAN":
                raise PersonTwinAuthorityReplayError("APPROVE requires HUMAN authorization identity")
            if auth["authorization_id"] != principal:
                raise PersonTwinAuthorityReplayError("APPROVE principal does not match authorization identity")

        policy_receipt_sha = _sha(policy_decision.get("receipt_sha256"), "policy.receipt_sha256")
        replay_identity: dict[str, Any] = {
            "tenant_id": identity["tenant_id"],
            "twin_id": identity["twin_id"],
            "identity_fingerprint": identity["identity_fingerprint"],
            "person_record_id": person_record["id"],
            "provenance_hash": _sha(person_record.get("provenance_hash"), "record.provenance_hash"),
            "source_record_id": person_record["source_record_id"],
            "source_content_hash": _sha(person_record.get("content_hash"), "record.content_hash"),
            "privacy_class": privacy,
            "scope": scope,
            "consent_receipt_id": consent_receipt["consent_receipt_id"],
            "consent_receipt_hash": consent_receipt["receipt_hash"],
            "current_revocation_ledger_hash": ledger_hash,
            "admission_session_id": admission["session_id"],
            "candidate_id": admission["candidate_id"],
            "candidate_sha256": admission["candidate_sha256"],
            "current_pointer_hash": admission["current_pointer_hash"],
            "policy_hash": _hash(dict(policy)),
            "policy_receipt_sha256": policy_receipt_sha,
            "principal_id": principal,
            **actor,
            "current_session_hash": session_hash,
            "authority_generation": current_session["authority_generation"],
            "challenge_id": current_session["challenge_id"],
            "challenge_sha256": current_session["challenge_sha256"],
            "ack_sha256": current_session["ack_sha256"],
            **auth,
            "action": action,
            "purpose": purpose,
        }
        replay_key = _stable_replay_key(replay_identity)
        replay_identity["replay_key"] = replay_key
        replay_hash = _hash(replay_identity)
        binding = dict(replay_identity)
        binding["replay_identity_hash"] = replay_hash

        durable = _read_durable_replay(replay_store, replay_key=replay_key)
        if durable is not None:
            if durable.get("replay_key") != replay_key:
                raise PersonTwinAuthorityReplayError("durable replay key lookup mismatch")
            if durable.get("replay_identity_hash") != replay_hash:
                return _receipt(
                    "DENY",
                    "REPLAY_IDENTITY_MISMATCH",
                    action,
                    at,
                    binding=binding,
                    replay_status="DIVERGENT_DENIED",
                    policy_sha=policy_receipt_sha,
                )
            return _receipt(
                "ALLOW",
                "EXACT_REPLAY_IDEMPOTENT",
                action,
                at,
                binding=binding,
                replay_status="EXACT_IDEMPOTENT",
                policy_sha=policy_receipt_sha,
            )
        return _receipt(
            "ALLOW",
            "PERSON_TWIN_AUTHORITY_ALLOW",
            action,
            at,
            binding=binding,
            replay_status="NEW",
            policy_sha=policy_receipt_sha,
        )
    except Exception as exc:
        return _receipt("DENY", f"FAIL_CLOSED:{type(exc).__name__}:{exc}", action, at)
