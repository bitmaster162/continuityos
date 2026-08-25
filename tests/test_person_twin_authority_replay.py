from __future__ import annotations

import copy
import hashlib
import json

import pytest

from continuityos.company_twin_ingest import normalize_envelope
from continuityos.person_twin_admission_contracts import (
    build_consent_revocation_entry,
    build_consent_revocation_ledger,
    build_person_twin_identity,
    build_source_consent_receipt,
)
from continuityos.person_twin_admission_coordinator import (
    AdmissionStoreConflict,
    PersonTwinAdmissionCoordinator,
)
from continuityos.person_twin_authority_replay import (
    SCHEMA_VERSION,
    evaluate_person_twin_authority_replay,
)
from continuityos.person_twin_privacy_provenance import (
    build_person_twin_provenance,
    canonical_person_private_scope,
    deterministic_source_identity_hash,
)

AT = "2026-08-25T12:50:00Z"


def _canonical_bytes(value) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _hash(value) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha(value: bytes | None) -> str | None:
    return None if value is None else hashlib.sha256(value).hexdigest()


class Store:
    def __init__(self):
        self.pointer = b'{"candidate":"last-known-good"}'
        self.candidates: dict[str, bytes] = {}

    def read_current_pointer_bytes(self):
        return self.pointer

    def read_candidate_bytes(self, candidate_id):
        return self.candidates.get(candidate_id)

    def commit_candidate_not_current(self, candidate_id, candidate_bytes):
        old = self.candidates.get(candidate_id)
        if old is not None and old != candidate_bytes:
            raise AdmissionStoreConflict("candidate conflict")
        self.candidates[candidate_id] = candidate_bytes

    def promote_current_pointer(self, *, expected_pointer_sha256, pointer_bytes):
        if _sha(self.pointer) != expected_pointer_sha256:
            raise AdmissionStoreConflict("stale pointer")
        self.pointer = pointer_bytes


class NullAdmissionStore:
    def read_current_pointer_bytes(self):
        return None

    def read_candidate_bytes(self, candidate_id):
        return None


class ReplayStore:
    def __init__(self):
        self.receipts: dict[str, bytes] = {}

    def read_replay_receipt_bytes(self, replay_key):
        return self.receipts.get(replay_key)

    def seed(self, receipt):
        self.receipts[receipt["replay_key"]] = _canonical_bytes(receipt)


class ExplodingReplayStore:
    def read_replay_receipt_bytes(self, replay_key):
        raise RuntimeError("synthetic read failure")


def _person():
    identity = build_person_twin_identity(
        tenant_id="tenant:person-pilot",
        subject_id="subject:owner",
        owner_id="human:owner",
        controller_id="human:owner",
        controller_kind="HUMAN",
        ownership_epoch=1,
        created_at="2026-08-25T00:00:00Z",
    )
    scope = canonical_person_private_scope(identity["twin_id"])
    source = normalize_envelope({
        "schema_version": "company-twin-source-envelope/1",
        "tenant_id": identity["tenant_id"],
        "connector_id": "connector:synthetic",
        "source_system": "synthetic_drive",
        "source_object_type": "document",
        "source_object_id": "doc-r4",
        "revision_id": "r1",
        "observed_at": "2026-08-25T10:01:00Z",
        "effective_at": "2026-08-25T10:00:00Z",
        "acl": {"visibility": "PERSONAL", "scope": scope},
        "payload": {"title": "R4", "text": "synthetic"},
        "raw_ref": "synthetic://r4/doc",
        "cursor": "cursor:r4",
        "actor": {
            "actor_id": "human:owner",
            "actor_kind": "HUMAN",
            "authority_class": "OWNER",
        },
        "deleted": False,
    })
    consent = build_source_consent_receipt(
        identity,
        authorizing_principal="human:owner",
        authorizing_principal_kind="HUMAN",
        source_system=source["source_system"],
        source_identity_hash=deterministic_source_identity_hash(source),
        allowed_object_types=["document"],
        allowed_scopes=[scope],
        purpose="person-memory",
        issued_at="2026-08-25T09:00:00Z",
        expires_at="2026-08-26T00:00:00Z",
        revoked_at=None,
        source_read_authority=False,
        memory_admission_authority=True,
        policy_version="p3-p1-r4r1-test/1",
    )
    ledger = build_consent_revocation_ledger()
    record = build_person_twin_provenance(
        identity,
        consent,
        ledger,
        source,
        admission_session_id="admission:r4r1:1",
        purpose="person-memory",
        at="2026-08-25T11:00:00Z",
    )
    store = Store()
    coordinator = PersonTwinAdmissionCoordinator(
        store,
        session_id=record["admission_session_id"],
        identity=identity,
        consent_receipt=consent,
        source_record=source,
        candidate_record=record,
        purpose="person-memory",
    )
    assert coordinator.validate(revocation_ledger=ledger, at="2026-08-25T11:10:00Z")["state"] == "VALIDATED"
    assert coordinator.commit_not_current(current_revocation_ledger=ledger, at="2026-08-25T11:20:00Z")["state"] == "COMMITTED_NOT_CURRENT"
    assert coordinator.postverify(current_revocation_ledger=ledger, at="2026-08-25T11:30:00Z")["state"] == "POSTVERIFY_PASS"
    admission = coordinator.promote_current(current_revocation_ledger=ledger, at="2026-08-25T11:40:00Z")
    assert admission["state"] == "CURRENT"
    pointer = json.loads(store.pointer.decode("utf-8"))
    return identity, source, consent, ledger, record, admission, pointer, store


def _policy(identity, *, revoked=False):
    scope = canonical_person_private_scope(identity["twin_id"])
    return {
        "schema_version": "company-twin-p2c/1",
        "tenant_id": identity["tenant_id"],
        "actors": [
            {
                "id": "actor:owner",
                "principal_id": "human:owner",
                "actor_kind": "HUMAN",
                "role": "DIRECTOR",
                "scopes": [scope],
            },
            {
                "id": "actor:agent",
                "principal_id": "agent:assistant",
                "actor_kind": "AGENT",
                "role": "AGENT",
                "scopes": [scope],
                "manager_actor_id": "actor:owner",
            },
        ],
        "grants": [{
            "id": "grant:owner",
            "actor_id": "actor:owner",
            "actions": ["READ", "PROPOSE", "APPROVE", "DELEGATE"],
            "scopes": [scope],
            "purposes": ["person-memory"],
        }],
        "delegations": [{
            "id": "delegation:agent",
            "grantor_actor_id": "actor:owner",
            "grantee_actor_id": "actor:agent",
            "actions": ["READ", "PROPOSE"],
            "scopes": [scope],
            "purposes": ["person-memory"],
            "parent_id": None,
            "expires_at": "2026-08-26T00:00:00Z",
            "revoked": False,
        }],
        "explicit_denies": [],
        "revoked_delegation_ids": ["delegation:agent"] if revoked else [],
    }


def _session():
    return {
        "schema": "continuityos.current_effect_boundary/v1",
        "mode": "CURRENT",
        "declared": True,
        "binding_verified": True,
        "reason": "EXACT_CURRENT_SESSION_VERIFIED",
        "authority_generation": "R64",
        "challenge_id": "challenge:r4r1:1",
        "challenge_sha256": "1" * 64,
        "ack_sha256": "2" * 64,
        "session_effect_ceiling": "READ_ONLY",
        "authority_ceiling": "NO_FURTHER_AGENT_WORK",
        "effects": {
            "legacy_fallback": False,
            "memory_write": False,
            "ledger_write": False,
            "filesystem_write": False,
            "network_effect": False,
            "server_started": False,
            "subprocess_execution": False,
            "deployment": False,
            "current_state_apply": False,
            "canonical_mutation": False,
            "external_message": False,
            "auto_dispatch": False,
            "trading": False,
            "wallet_access": False,
            "order_execution": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
        },
    }


def _authorization(
    *,
    auth_sha="6" * 64,
    auth_class="HUMAN",
    auth_id="human:owner",
):
    base = {
        "projection_sha256": "3" * 64,
        "event_cursor": 7,
        "event_chain_head": "4" * 64,
    }
    core = {
        "proposal_id": "proposal:r4r1:1",
        "proposal_file_sha256": "5" * 64,
        "project_id": "project:r4r1",
        "base": base,
        "operation_count": 1,
    }
    request = {
        "schema": "continuityos.operational_memory.apply_authorization_request/v1",
        "terminal": "CURRENT_MEMORY_APPLY_AUTH_REQUEST_PASS",
        "authorization_granted": False,
        "execution_authorized": False,
        "apply_status": "NOT_APPLIED",
        "request_id": "omar-" + _hash(core)[:40],
        "proposal_id": core["proposal_id"],
        "proposal_file_sha256": core["proposal_file_sha256"],
        "project_id": core["project_id"],
        "expected_base": base,
        "operation_count": 1,
    }
    preflight = {
        "schema": "continuityos.operational_memory.project_update_packet_preflight/v1",
        "terminal": "CURRENT_PROJECT_UPDATE_PREFLIGHT_READY",
        "packet_valid": True,
        "authorization_record_valid": True,
        "apply_ready": True,
        "execution_authorized": False,
        "packet_id": "packet:r4r1:1",
        "proposal_id": core["proposal_id"],
        "proposal_file_sha256": core["proposal_file_sha256"],
        "expected_base": base,
        "authorization_file_sha256": auth_sha,
        "authorization": {
            "class": auth_class,
            "id": auth_id,
            "ref": "synthetic://approval/r4r1",
        },
    }
    return request, preflight


def _inputs(*, principal="agent:assistant", action="READ"):
    identity, source, consent, ledger, record, admission, pointer, admission_store = _person()
    request, preflight = _authorization()
    return dict(
        identity=identity,
        consent_receipt=consent,
        current_revocation_ledger=ledger,
        source_record=source,
        person_record=record,
        admission_receipt=admission,
        current_pointer=pointer,
        admission_store=admission_store,
        policy=_policy(identity),
        principal_id=principal,
        action=action,
        requested_scope=record["scope"],
        requested_privacy_class=record["privacy_class"],
        purpose="person-memory",
        at=AT,
        current_session=_session(),
        authorization_request=request,
        authorization_preflight=preflight,
        replay_store=ReplayStore(),
    )


def test_agent_read_and_propose_are_non_effectful_allows():
    for action in ("READ", "PROPOSE"):
        result = evaluate_person_twin_authority_replay(**_inputs(action=action))
        assert result["schema_version"] == SCHEMA_VERSION
        assert result["decision"] == "ALLOW"
        assert result["replay_status"] == "NEW"
        assert result["mutated"] is False
        assert result["current_state_apply"] is False
        assert result["canonical_mutation"] is False
        assert result["execution_authorized"] is False
        assert result["production_admission_status"] == "NOT_PRODUCTION_ADMITTED"
        assert result["execution_authority"] == "NONE"
        assert result["can_execute"] is False
        assert result["can_trade"] is False
        assert result["capital_permission"] == "DENY"


def test_human_approve_is_decision_only_and_agent_approve_is_denied():
    human = evaluate_person_twin_authority_replay(
        **_inputs(principal="human:owner", action="APPROVE")
    )
    assert human["decision"] == "ALLOW"
    assert human["execution_authorized"] is False
    agent = evaluate_person_twin_authority_replay(**_inputs(action="APPROVE"))
    assert agent["decision"] == "DENY"
    assert "AGENT_AUTHORITY_CEILING" in agent["reason"]


@pytest.mark.parametrize(
    "action, needle",
    [("EXECUTE", "EXECUTE unsupported"), ("EXPORT", "action outside R4 scope")],
)
def test_effectful_or_r5_actions_are_not_in_r4(action, needle):
    result = evaluate_person_twin_authority_replay(**_inputs(action=action))
    assert result["decision"] == "DENY"
    assert needle in result["reason"]
    assert result["execution_authorized"] is False


def test_caller_self_attested_current_without_store_readback_is_denied():
    x = _inputs()
    x["admission_store"] = NullAdmissionStore()
    result = evaluate_person_twin_authority_replay(**x)
    assert result["decision"] == "DENY"
    assert "current candidate missing from admission store" in result["reason"]


def test_caller_current_pointer_must_equal_independent_store_readback():
    x = _inputs()
    x["current_pointer"] = {**x["current_pointer"], "challenge": "forged"}
    result = evaluate_person_twin_authority_replay(**x)
    assert result["decision"] == "DENY"
    assert "caller current pointer differs from admission readback" in result["reason"]


def test_candidate_byte_drift_in_admission_store_is_denied():
    x = _inputs()
    x["admission_store"].candidates[x["person_record"]["id"]] = b"{}"
    result = evaluate_person_twin_authority_replay(**x)
    assert result["decision"] == "DENY"
    assert "candidate byte readback mismatch" in result["reason"]


def test_pointer_byte_drift_in_admission_store_is_denied():
    x = _inputs()
    x["admission_store"].pointer = _canonical_bytes({"state": "CURRENT", "candidate_id": "other"})
    result = evaluate_person_twin_authority_replay(**x)
    assert result["decision"] == "DENY"
    assert "caller current pointer differs from admission readback" in result["reason"]


def test_current_session_requires_exact_no_further_agent_work_ceiling():
    x = _inputs()
    x["current_session"] = {
        **x["current_session"],
        "authority_ceiling": "EXECUTION_ALLOWED",
    }
    result = evaluate_person_twin_authority_replay(**x)
    assert result["decision"] == "DENY"
    assert "current session authority ceiling mismatch" in result["reason"]


@pytest.mark.parametrize(
    "mutation, needle",
    [
        ("scope", "requested privacy/scope identity drift"),
        ("privacy", "requested privacy/scope identity drift"),
        ("tenant", "policy tenant identity mismatch"),
        ("effect", "current session effect ceiling widened"),
        ("proposal", "authorization proposal identity mismatch"),
        ("request", "authorization request_id integrity mismatch"),
        ("provenance", "provenance_hash mismatch"),
    ],
)
def test_identity_and_authority_drift_fail_closed(mutation, needle):
    x = _inputs()
    if mutation == "scope":
        x["requested_scope"] = "team:ops"
    elif mutation == "privacy":
        x["requested_privacy_class"] = "COMPANY"
    elif mutation == "tenant":
        x["policy"] = {**x["policy"], "tenant_id": "tenant:other"}
    elif mutation == "effect":
        x["current_session"] = copy.deepcopy(x["current_session"])
        x["current_session"]["effects"]["filesystem_write"] = True
    elif mutation == "proposal":
        x["authorization_preflight"] = {
            **x["authorization_preflight"],
            "proposal_id": "proposal:other",
        }
    elif mutation == "request":
        x["authorization_request"] = {
            **x["authorization_request"],
            "request_id": "omar-forged",
        }
    elif mutation == "provenance":
        x["person_record"] = {
            **x["person_record"],
            "provenance_hash": "f" * 64,
        }
    result = evaluate_person_twin_authority_replay(**x)
    assert result["decision"] == "DENY"
    assert needle in result["reason"]


def test_revocation_and_ledger_drift_fail_closed_even_for_prior_allow():
    for revoked_at in ("2026-08-25T12:45:00Z", "2026-08-25T23:30:00Z"):
        x = _inputs()
        entry = build_consent_revocation_entry(
            x["identity"],
            x["consent_receipt"],
            revoking_principal="human:owner",
            revoking_principal_kind="HUMAN",
            revoked_at=revoked_at,
            reason="synthetic R4R1 revoke",
        )
        x["current_revocation_ledger"] = build_consent_revocation_ledger([entry])
        result = evaluate_person_twin_authority_replay(**x)
        assert result["decision"] == "DENY"
        assert "current revocation ledger identity drift" in result["reason"]


def test_revoked_delegation_denies_agent():
    x = _inputs()
    x["policy"] = _policy(x["identity"], revoked=True)
    result = evaluate_person_twin_authority_replay(**x)
    assert result["decision"] == "DENY"
    assert "NO_MATCHING_GRANT" in result["reason"]


def test_human_approve_principal_must_match_human_authorization_identity():
    x = _inputs(principal="human:owner", action="APPROVE")
    request, preflight = _authorization(auth_id="human:other")
    x["authorization_request"] = request
    x["authorization_preflight"] = preflight
    result = evaluate_person_twin_authority_replay(**x)
    assert result["decision"] == "DENY"
    assert "APPROVE principal does not match authorization identity" in result["reason"]


def test_human_approve_rejects_deterministic_controller_authorization():
    x = _inputs(principal="human:owner", action="APPROVE")
    request, preflight = _authorization(
        auth_class="DETERMINISTIC_CONTROLLER",
        auth_id="controller:r4r1",
    )
    x["authorization_request"] = request
    x["authorization_preflight"] = preflight
    result = evaluate_person_twin_authority_replay(**x)
    assert result["decision"] == "DENY"
    assert "APPROVE requires HUMAN authorization identity" in result["reason"]


def test_exact_replay_requires_anchored_readback_and_is_idempotent():
    x = _inputs()
    first = evaluate_person_twin_authority_replay(**x)
    assert first["decision"] == "ALLOW" and first["replay_status"] == "NEW"
    x["replay_store"].seed(first)
    exact = evaluate_person_twin_authority_replay(**copy.deepcopy(x))
    assert exact["decision"] == "ALLOW"
    assert exact["reason"] == "EXACT_REPLAY_IDEMPOTENT"
    assert exact["replay_status"] == "EXACT_IDEMPOTENT"
    assert exact["replay_identity_hash"] == first["replay_identity_hash"]
    assert exact["mutated"] is False


def test_divergent_authorization_under_same_stable_replay_key_is_denied():
    x = _inputs()
    first = evaluate_person_twin_authority_replay(**x)
    x["replay_store"].seed(first)
    request, preflight = _authorization(auth_sha="7" * 64)
    x["authorization_request"] = request
    x["authorization_preflight"] = preflight
    denied = evaluate_person_twin_authority_replay(**x)
    assert denied["decision"] == "DENY"
    assert denied["reason"] == "REPLAY_IDENTITY_MISMATCH"
    assert denied["replay_status"] == "DIVERGENT_DENIED"


def test_rehashed_forged_durable_receipt_is_rejected_by_binding_rederivation():
    x = _inputs()
    first = evaluate_person_twin_authority_replay(**x)
    forged = copy.deepcopy(first)
    forged["binding"]["principal_id"] = "attacker"
    body = dict(forged)
    body.pop("receipt_hash")
    forged["receipt_hash"] = _hash(body)
    x["replay_store"].receipts[first["replay_key"]] = _canonical_bytes(forged)
    denied = evaluate_person_twin_authority_replay(**x)
    assert denied["decision"] == "DENY"
    assert "durable replay identity binding mismatch" in denied["reason"]


def test_durable_replay_byte_drift_is_denied():
    x = _inputs()
    first = evaluate_person_twin_authority_replay(**x)
    x["replay_store"].receipts[first["replay_key"]] = _canonical_bytes(first) + b"\n"
    denied = evaluate_person_twin_authority_replay(**x)
    assert denied["decision"] == "DENY"
    assert "durable replay receipt bytes are not canonical" in denied["reason"]


def test_durable_replay_read_failure_fails_closed():
    x = _inputs()
    x["replay_store"] = ExplodingReplayStore()
    denied = evaluate_person_twin_authority_replay(**x)
    assert denied["decision"] == "DENY"
    assert "durable replay readback failed" in denied["reason"]


def test_deterministic_new_receipt_for_identical_inputs():
    x = _inputs()
    first = evaluate_person_twin_authority_replay(**x)
    second = evaluate_person_twin_authority_replay(**copy.deepcopy(x))
    assert first == second
