"""Trusted authenticated Human approval boundary for governed delivery.

R17 converts an R16 HUMAN_MERGE_GATE_REQUEST into cryptographically authenticated
merge eligibility. It never executes a merge, deploy, runtime action, trade, or capital action.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping

from .governed_delivery_pipeline import require_human_merge_gate_request_current

SCHEMA = "continuityos.trusted_human_approval/v1"
REGISTRY_SCHEMA = "continuityos.trusted_human_key_registry/v1"
APPROVAL_SCHEMA = "continuityos.trusted_human_approval_envelope/v1"
ELIGIBILITY_SCHEMA = "continuityos.trusted_human_merge_eligibility/v1"
PURPOSE = "CONTINUITYOS_HUMAN_MERGE_APPROVAL"
ALGORITHM = "Ed25519"
DOMAIN = b"continuityos.trusted_human_approval/v1\0"
MAX_TTL_SECONDS = 900
MAX_CLOCK_SKEW_SECONDS = 60
MAX_KEYS = 32

_SAFE_AUTHORITY_ITEMS = (
    ("execution_authority", "NONE"),
    ("can_execute", False),
    ("deploy_permission", "DENY"),
    ("can_trade", False),
    ("capital_permission", "DENY"),
)

def _safe_authority() -> dict[str, Any]:
    return dict(_SAFE_AUTHORITY_ITEMS)


class InMemoryApprovalReplayGuard:
    """Atomic single-process replay guard; production may supply a durable equivalent."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consumed: set[str] = set()

    def consume_once(self, approval_id: str) -> bool:
        with self._lock:
            if approval_id in self._consumed:
                return False
            self._consumed.add(approval_id)
            return True

    def contains(self, approval_id: str) -> bool:
        with self._lock:
            return approval_id in self._consumed


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Mapping[str, Any]) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _string(name: str, value: Any, *, maximum: int = 256) -> str:
    if type(value) is not str or not value or len(value) > maximum or any(ord(ch) < 32 for ch in value):
        raise ValueError(f"trusted human approval: invalid {name}")
    return value


def _hex(name: str, value: Any, *, length: int) -> str:
    text = _string(name, value, maximum=length)
    if len(text) != length or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError(f"trusted human approval: invalid {name}")
    return text


def _decode_b64u(name: str, value: Any, *, expected_len: int) -> bytes:
    text = _string(name, value, maximum=((expected_len + 2) // 3) * 4 + 4)
    if "=" in text:
        raise ValueError(f"trusted human approval: non-canonical {name}")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))
    except Exception as exc:
        raise ValueError(f"trusted human approval: invalid {name}") from exc
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if canonical != text or len(raw) != expected_len:
        raise ValueError(f"trusted human approval: invalid {name}")
    return raw


def _load_ed25519_backend():
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except (ImportError, ModuleNotFoundError) as exc:
        raise ValueError("trusted human approval: ed25519 backend unavailable") from exc
    return Ed25519PublicKey, InvalidSignature, UnsupportedAlgorithm


def _verify_ed25519(*, public_key: bytes, signature: bytes, message: bytes) -> None:
    Ed25519PublicKey, InvalidSignature, UnsupportedAlgorithm = _load_ed25519_backend()
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature as exc:
        raise ValueError("trusted human approval: signature invalid") from exc
    except UnsupportedAlgorithm as exc:
        raise ValueError("trusted human approval: ed25519 backend unavailable") from exc
    except ValueError as exc:
        raise ValueError("trusted human approval: public key invalid") from exc


def _registry_entry(registry: Any, *, signer_id: str, key_id: str, pinned_registry_sha256: str) -> bytes:
    if type(registry) is not dict or set(registry) != {"schema", "keys"}:
        raise ValueError("trusted human approval: registry shape invalid")
    if registry.get("schema") != REGISTRY_SCHEMA or type(registry.get("keys")) is not list:
        raise ValueError("trusted human approval: registry contract invalid")
    if len(registry["keys"]) > MAX_KEYS:
        raise ValueError("trusted human approval: registry too large")
    matches = []
    for item in registry["keys"]:
        if type(item) is not dict or set(item) != {"signer_id", "key_id", "algorithm", "public_key_b64u", "active"}:
            raise ValueError("trusted human approval: registry key shape invalid")
        item_signer = _string("registry signer_id", item["signer_id"], maximum=96)
        item_key = _string("registry key_id", item["key_id"], maximum=96)
        if item["algorithm"] != ALGORITHM or type(item["active"]) is not bool:
            raise ValueError("trusted human approval: registry key contract invalid")
        _decode_b64u("public_key_b64u", item["public_key_b64u"], expected_len=32)
        if item_signer == signer_id and item_key == key_id:
            matches.append(item)
    pin = _hex("pinned_registry_sha256", pinned_registry_sha256, length=64)
    if _sha256_json(registry) != pin:
        raise ValueError("trusted human approval: registry pin mismatch")
    if len(matches) != 1:
        raise ValueError("trusted human approval: trusted key not uniquely found")
    entry = matches[0]
    if entry["algorithm"] != ALGORITHM or entry["active"] is not True:
        raise ValueError("trusted human approval: trusted key inactive or unsupported")
    return _decode_b64u("public_key_b64u", entry["public_key_b64u"], expected_len=32)


def _signed_payload(envelope: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "schema", "purpose", "algorithm", "signer_id", "key_id", "request_receipt_id", "repository",
        "work_order_id", "generation", "policy_version", "baseline_sha", "candidate_sha",
        "candidate_tree_sha", "parity_mode", "expected_delta_sha256", "observed_delta_sha256",
        "approve_expected_delta", "decision", "issued_at_unix", "expires_at_unix", "approval_nonce",
    )
    if set(envelope) != set(keys) | {"signature_b64u"}:
        raise ValueError("trusted human approval: envelope shape invalid")
    return {key: envelope[key] for key in keys}


def approval_signing_message(envelope_without_signature: Mapping[str, Any]) -> bytes:
    if type(envelope_without_signature) is not dict:
        raise ValueError("trusted human approval: signing payload must be dict")
    return DOMAIN + _canonical_bytes(envelope_without_signature)


@dataclass(frozen=True)
class HumanApprovalResult:
    eligibility_receipt: dict[str, Any]
    approval_id: str


def verify_and_consume_human_approval(
    *,
    request_receipt: Any,
    approval_envelope: Any,
    trusted_key_registry: Any,
    pinned_registry_sha256: str,
    repository: str,
    current_base_sha: str,
    current_head_sha: str,
    current_tree_sha: str,
    now_unix: int,
    replay_guard: Any,
) -> HumanApprovalResult:
    request = require_human_merge_gate_request_current(
        request_receipt,
        repository=repository,
        current_base_sha=current_base_sha,
        current_head_sha=current_head_sha,
        current_tree_sha=current_tree_sha,
    )
    if type(approval_envelope) is not dict:
        raise ValueError("trusted human approval: envelope must be dict")
    envelope = dict(approval_envelope)
    signed = _signed_payload(envelope)
    if signed["schema"] != APPROVAL_SCHEMA or signed["purpose"] != PURPOSE or signed["algorithm"] != ALGORITHM:
        raise ValueError("trusted human approval: envelope contract invalid")
    if signed["decision"] != "APPROVE":
        raise ValueError("trusted human approval: decision is not APPROVE")
    signer_id = _string("signer_id", signed["signer_id"], maximum=96)
    key_id = _string("key_id", signed["key_id"], maximum=96)
    nonce = _hex("approval_nonce", signed["approval_nonce"], length=64)
    if type(now_unix) is not int or now_unix < 0:
        raise ValueError("trusted human approval: invalid now_unix")
    issued = signed["issued_at_unix"]
    expires = signed["expires_at_unix"]
    if type(issued) is not int or type(expires) is not int or issued < 0 or expires <= issued:
        raise ValueError("trusted human approval: invalid approval lifetime")
    if expires - issued > MAX_TTL_SECONDS:
        raise ValueError("trusted human approval: approval TTL exceeds policy")
    if issued > now_unix + MAX_CLOCK_SKEW_SECONDS:
        raise ValueError("trusted human approval: approval issued in future")
    if now_unix > expires:
        raise ValueError("trusted human approval: approval expired")

    expected_bindings = {
        "request_receipt_id": request["receipt_id"],
        "repository": request["repository"],
        "work_order_id": request["work_order_id"],
        "generation": request["generation"],
        "policy_version": request["policy_version"],
        "baseline_sha": request["baseline_sha"],
        "candidate_sha": request["candidate_sha"],
        "candidate_tree_sha": request["candidate_tree_sha"],
        "parity_mode": request["parity_mode"],
        "expected_delta_sha256": request["expected_delta_sha256"],
        "observed_delta_sha256": request["observed_delta_sha256"],
    }
    for key, expected in expected_bindings.items():
        if signed.get(key) != expected:
            raise ValueError(f"trusted human approval: binding mismatch for {key}")
    must_approve_delta = request["human_delta_approval_required"] is True
    if signed["approve_expected_delta"] is not must_approve_delta:
        raise ValueError("trusted human approval: explicit delta approval mismatch")

    public_key = _registry_entry(
        trusted_key_registry,
        signer_id=signer_id,
        key_id=key_id,
        pinned_registry_sha256=pinned_registry_sha256,
    )
    signature = _decode_b64u("signature_b64u", envelope["signature_b64u"], expected_len=64)
    _verify_ed25519(public_key=public_key, signature=signature, message=approval_signing_message(signed))

    approval_id = "hap_" + _sha256_json(signed)

    eligibility = {
        "schema": ELIGIBILITY_SCHEMA,
        "stage": "HUMAN_APPROVAL_BOUNDARY",
        "status": "MERGE_ELIGIBLE",
        "approval_id": approval_id,
        "request_receipt_id": request["receipt_id"],
        "repository": request["repository"],
        "work_order_id": request["work_order_id"],
        "generation": request["generation"],
        "policy_version": request["policy_version"],
        "baseline_sha": request["baseline_sha"],
        "candidate_sha": request["candidate_sha"],
        "candidate_tree_sha": request["candidate_tree_sha"],
        "parity_mode": request["parity_mode"],
        "expected_delta_sha256": request["expected_delta_sha256"],
        "observed_delta_sha256": request["observed_delta_sha256"],
        "human_delta_approved": must_approve_delta,
        "authenticated_human_approval_present": True,
        "signer_id": signer_id,
        "key_id": key_id,
        "registry_sha256": _hex("pinned_registry_sha256", pinned_registry_sha256, length=64),
        "request_receipt": dict(request),
        "approval_envelope": dict(envelope),
        "approval_nonce": nonce,
        "issued_at_unix": issued,
        "expires_at_unix": expires,
        "merge_authority": "HUMAN_APPROVED_EXACT_CANDIDATE",
        "can_merge": True,
        **_safe_authority(),
    }
    eligibility["receipt_id"] = "hme_" + _sha256_json(eligibility)
    consume_once = getattr(replay_guard, "consume_once", None)
    if not callable(consume_once):
        raise ValueError("trusted human approval: replay guard contract invalid")
    if consume_once(approval_id) is not True:
        raise ValueError("trusted human approval: approval replay detected")
    return HumanApprovalResult(dict(eligibility), approval_id)


def require_merge_eligibility_current(
    eligibility_receipt: Any,
    *,
    trusted_key_registry: Any,
    pinned_registry_sha256: str,
    repository: str,
    current_base_sha: str,
    current_head_sha: str,
    current_tree_sha: str,
    now_unix: int,
) -> dict[str, Any]:
    if type(eligibility_receipt) is not dict:
        raise ValueError("trusted human approval: eligibility must be dict")
    receipt = dict(eligibility_receipt)
    rid = receipt.pop("receipt_id", None)
    if rid != "hme_" + _sha256_json(receipt):
        raise ValueError("trusted human approval: eligibility receipt tampered")
    receipt["receipt_id"] = rid
    if (
        receipt.get("schema") != ELIGIBILITY_SCHEMA
        or receipt.get("stage") != "HUMAN_APPROVAL_BOUNDARY"
        or receipt.get("status") != "MERGE_ELIGIBLE"
        or receipt.get("authenticated_human_approval_present") is not True
    ):
        raise ValueError("trusted human approval: eligibility contract invalid")
    if receipt.get("can_merge") is not True or receipt.get("merge_authority") != "HUMAN_APPROVED_EXACT_CANDIDATE":
        raise ValueError("trusted human approval: merge authority invalid")
    for key, expected in _SAFE_AUTHORITY_ITEMS:
        if receipt.get(key) != expected:
            raise ValueError(f"trusted human approval: unsafe authority field {key}")
    if receipt.get("registry_sha256") != _hex("pinned_registry_sha256", pinned_registry_sha256, length=64):
        raise ValueError("trusted human approval: eligibility registry pin mismatch")
    nested_request = receipt.get("request_receipt")
    if type(nested_request) is not dict:
        raise ValueError("trusted human approval: eligibility missing R16 request")
    validated_request = require_human_merge_gate_request_current(
        nested_request, repository=repository, current_base_sha=current_base_sha,
        current_head_sha=current_head_sha, current_tree_sha=current_tree_sha,
    )
    if validated_request.get("receipt_id") != receipt.get("request_receipt_id"):
        raise ValueError("trusted human approval: eligibility R16 request binding mismatch")
    if receipt.get("repository") != repository:
        raise ValueError("trusted human approval: merge eligibility repository drift")
    if receipt.get("baseline_sha") != current_base_sha or receipt.get("candidate_sha") != current_head_sha or receipt.get("candidate_tree_sha") != current_tree_sha:
        raise ValueError("trusted human approval: merge eligibility stale due to revision drift")
    if type(now_unix) is not int or now_unix < 0:
        raise ValueError("trusted human approval: invalid now_unix")

    envelope = receipt.get("approval_envelope")
    if type(envelope) is not dict:
        raise ValueError("trusted human approval: eligibility missing signed envelope")
    signed = _signed_payload(envelope)
    if signed["schema"] != APPROVAL_SCHEMA or signed["purpose"] != PURPOSE or signed["algorithm"] != ALGORITHM:
        raise ValueError("trusted human approval: eligibility envelope contract invalid")
    issued = signed.get("issued_at_unix")
    expires = signed.get("expires_at_unix")
    if type(issued) is not int or type(expires) is not int or issued < 0 or expires <= issued:
        raise ValueError("trusted human approval: invalid approval lifetime")
    if expires - issued > MAX_TTL_SECONDS:
        raise ValueError("trusted human approval: approval TTL exceeds policy")
    if issued > now_unix + MAX_CLOCK_SKEW_SECONDS:
        raise ValueError("trusted human approval: approval issued in future")
    if now_unix > expires:
        raise ValueError("trusted human approval: merge eligibility expired")
    public_key = _registry_entry(
        trusted_key_registry,
        signer_id=_string("signer_id", signed["signer_id"], maximum=96),
        key_id=_string("key_id", signed["key_id"], maximum=96),
        pinned_registry_sha256=pinned_registry_sha256,
    )
    signature = _decode_b64u("signature_b64u", envelope["signature_b64u"], expected_len=64)
    _verify_ed25519(public_key=public_key, signature=signature, message=approval_signing_message(signed))

    signed_to_receipt = {
        "request_receipt_id": "request_receipt_id",
        "repository": "repository",
        "work_order_id": "work_order_id",
        "generation": "generation",
        "policy_version": "policy_version",
        "baseline_sha": "baseline_sha",
        "candidate_sha": "candidate_sha",
        "candidate_tree_sha": "candidate_tree_sha",
        "parity_mode": "parity_mode",
        "expected_delta_sha256": "expected_delta_sha256",
        "observed_delta_sha256": "observed_delta_sha256",
        "signer_id": "signer_id",
        "key_id": "key_id",
        "approval_nonce": "approval_nonce",
        "issued_at_unix": "issued_at_unix",
        "expires_at_unix": "expires_at_unix",
    }
    for signed_key, receipt_key in signed_to_receipt.items():
        if signed.get(signed_key) != receipt.get(receipt_key):
            raise ValueError(f"trusted human approval: eligibility binding mismatch for {receipt_key}")
    if signed.get("decision") != "APPROVE":
        raise ValueError("trusted human approval: eligibility decision invalid")
    expected_delta_approval = receipt.get("parity_mode") == "INTENTIONAL_CHANGE"
    if signed.get("approve_expected_delta") is not expected_delta_approval or receipt.get("human_delta_approved") is not expected_delta_approval:
        raise ValueError("trusted human approval: eligibility delta approval mismatch")
    approval_id = "hap_" + _sha256_json(signed)
    if receipt.get("approval_id") != approval_id:
        raise ValueError("trusted human approval: eligibility approval id mismatch")
    return dict(receipt)


__all__ = [
    "SCHEMA", "REGISTRY_SCHEMA", "APPROVAL_SCHEMA", "ELIGIBILITY_SCHEMA", "PURPOSE", "ALGORITHM",
    "MAX_TTL_SECONDS", "MAX_CLOCK_SKEW_SECONDS", "MAX_KEYS", "InMemoryApprovalReplayGuard",
    "HumanApprovalResult", "approval_signing_message",
    "verify_and_consume_human_approval", "require_merge_eligibility_current",
]
