from __future__ import annotations

import ast
import base64
import copy
import hashlib
import inspect
import json

import pytest

import continuityos.cross_ai_ruap_receipt_acceptance_origin_verifier as verifier


TRUSTED_REGISTRY_SHA256 = "a8ff59202759b53999e7ce69e79d8c8f0d7619c32b1f4b65ee8f87d998f19f11"
TRUSTED_PUBLIC_KEY_B64U = "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc"
TRUSTED_KEY_ID = "ed25519-sha256:10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d"
TRUSTED_SIGNATURE_B64U = (
    "DEvnyKwqkNIn42YSDmRsBGJAX03zNQdpAVYTl2JUH_ltYzm8jtDP4f-E-oKBHihi"
    "lZRJs9F481EFz1TFbTtWCw"
)
ATTACKER_PUBLIC_KEY_B64U = "oJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPA"
ATTACKER_KEY_ID = "ed25519-sha256:1325b850c2871916eae203f0efc3c8987f64e5e3cdb27679e6d1fa97808357e6"
ATTACKER_SIGNATURE_B64U = (
    "P9ubATV7TQSXXh0qStrfpyAMIyEOdXC4re4pFBogDm8nQD7wZl_btmnF7R2wttUH"
    "w4sAVF3Gc6PfP02PJs9gAw"
)
ACCEPTANCE_SHA256 = "8f7b8e0cfe03a09862ffe047c7cc2bcfdf9d3c3b05e72467afc4921fcfb0078d"


def accepted_receipt() -> dict:
    return {
        "schema": "continuityos.cross_ai_ruap_receipt_acceptance/v1",
        "mode": "EVIDENCE_ONLY",
        "acceptance_class": "STRUCTURAL_SELF_CONSISTENCY_ONLY",
        "transport_id": "xrt_" + "1" * 64,
        "source_client": "claude",
        "target_client": "cursor",
        "ruap_evidence": {
            "schema": "ruap.snapshot/v1",
            "snapshot_sha256": "2" * 64,
            "source_count": 2,
            "observation_count": 5,
            "freshness_required": True,
            "authority_ceiling": "OBSERVE_ONLY",
            "authority_class": "EVIDENCE_ONLY",
        },
        "verification": {
            "shape_verified": True,
            "integrity_checked": True,
            "authenticity_verified": False,
            "provenance_verified": False,
            "signer_identity_verified": False,
            "current_truth_promoted": False,
        },
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def trusted_registry(*, state: str = "ACTIVE") -> dict:
    return {
        "schema": "continuityos.cross_ai_ruap_acceptance_origin_key_registry/v1",
        "registry_id": "continuityos-cross-ai-acceptance-origin-r1",
        "keys": [
            {
                "producer_id": "fixture-producer-a",
                "key_id": TRUSTED_KEY_ID,
                "algorithm": "Ed25519",
                "public_key_b64u": TRUSTED_PUBLIC_KEY_B64U,
                "usage": "CROSS_AI_RUAP_RECEIPT_ACCEPTANCE_ORIGIN",
                "state": state,
            }
        ],
    }


def trusted_signature() -> dict:
    return {
        "schema": "continuityos.cross_ai_ruap_receipt_acceptance_origin_signature/v1",
        "purpose": "CROSS_AI_RUAP_RECEIPT_ACCEPTANCE_ORIGIN",
        "producer_id": "fixture-producer-a",
        "key_id": TRUSTED_KEY_ID,
        "algorithm": "Ed25519",
        "acceptance_sha256": ACCEPTANCE_SHA256,
        "signature_b64u": TRUSTED_SIGNATURE_B64U,
    }


def attacker_registry() -> dict:
    return {
        "schema": "continuityos.cross_ai_ruap_acceptance_origin_key_registry/v1",
        "registry_id": "continuityos-cross-ai-acceptance-origin-r1",
        "keys": [
            {
                "producer_id": "attacker-producer",
                "key_id": ATTACKER_KEY_ID,
                "algorithm": "Ed25519",
                "public_key_b64u": ATTACKER_PUBLIC_KEY_B64U,
                "usage": "CROSS_AI_RUAP_RECEIPT_ACCEPTANCE_ORIGIN",
                "state": "ACTIVE",
            }
        ],
    }


def attacker_signature() -> dict:
    return {
        "schema": "continuityos.cross_ai_ruap_receipt_acceptance_origin_signature/v1",
        "purpose": "CROSS_AI_RUAP_RECEIPT_ACCEPTANCE_ORIGIN",
        "producer_id": "attacker-producer",
        "key_id": ATTACKER_KEY_ID,
        "algorithm": "Ed25519",
        "acceptance_sha256": ACCEPTANCE_SHA256,
        "signature_b64u": ATTACKER_SIGNATURE_B64U,
    }


def canonical_sha256(value) -> str:
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def verify(
    *,
    accepted: dict | None = None,
    registry: dict | None = None,
    signature: dict | None = None,
):
    return verifier.verify_cross_ai_ruap_receipt_acceptance_origin(
        accepted_receipt=accepted if accepted is not None else accepted_receipt(),
        key_registry=registry if registry is not None else trusted_registry(),
        signature_envelope=signature if signature is not None else trusted_signature(),
    )


def pin_trusted_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    assert canonical_sha256(trusted_registry()) == TRUSTED_REGISTRY_SHA256
    monkeypatch.setattr(verifier, "PINNED_REGISTRY_SHA256", TRUSTED_REGISTRY_SHA256)


def test_default_r1_pin_is_canonical_empty_registry_and_trust_is_unprovisioned() -> None:
    empty = {
        "schema": verifier.REGISTRY_SCHEMA,
        "registry_id": verifier.REGISTRY_ID,
        "keys": [],
    }
    assert canonical_sha256(empty) == verifier.PINNED_REGISTRY_SHA256
    result = verify()
    assert result.ok is False
    assert result.acceptance_origin_verified is False
    assert result.errors == ("registry_sha256_mismatch",)


def test_real_cryptography_backend_accepts_precomputed_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("cryptography")
    pin_trusted_registry(monkeypatch)
    result = verify()
    assert result.ok is True
    assert result.errors == ()
    assert result.acceptance_origin_verified is True
    assert result.expected_acceptance_sha256 == ACCEPTANCE_SHA256
    assert result.expected_registry_sha256 == TRUSTED_REGISTRY_SHA256
    assert result.producer_id == "fixture-producer-a"
    assert result.key_id == TRUSTED_KEY_ID


def test_real_cryptography_backend_rejects_signature_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("cryptography")
    pin_trusted_registry(monkeypatch)
    signature = trusted_signature()
    raw = bytearray(base64.urlsafe_b64decode(signature["signature_b64u"] + "=="))
    raw[0] ^= 1
    signature["signature_b64u"] = (
        base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")
    )
    result = verify(signature=signature)
    assert result.ok is False
    assert result.acceptance_origin_verified is False
    assert result.errors == ("ed25519_signature_invalid",)


def test_attacker_key_and_valid_attacker_signature_cannot_replace_pinned_registry() -> None:
    assert canonical_sha256(attacker_registry()) != verifier.PINNED_REGISTRY_SHA256
    result = verify(registry=attacker_registry(), signature=attacker_signature())
    assert result.ok is False
    assert result.acceptance_origin_verified is False
    assert result.errors == ("registry_sha256_mismatch",)


def test_backend_unavailable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    pin_trusted_registry(monkeypatch)

    def unavailable():
        raise ValueError("ed25519_backend_unavailable")

    monkeypatch.setattr(verifier, "_load_ed25519_backend", unavailable)
    result = verify()
    assert result.ok is False
    assert result.acceptance_origin_verified is False
    assert result.errors == ("ed25519_backend_unavailable",)


def test_acceptance_digest_mismatch_fails_before_crypto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin_trusted_registry(monkeypatch)
    accepted = accepted_receipt()
    accepted["ruap_evidence"]["observation_count"] += 1
    result = verify(accepted=accepted)
    assert result.errors == ("acceptance_sha256_mismatch",)
    assert result.acceptance_origin_verified is False


@pytest.mark.parametrize("state", ["RETIRED", "REVOKED"])
def test_non_active_key_fails_closed(
    state: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = trusted_registry(state=state)
    monkeypatch.setattr(
        verifier, "PINNED_REGISTRY_SHA256", canonical_sha256(registry)
    )
    result = verify(registry=registry)
    assert result.errors == ("origin_key_not_active",)
    assert result.acceptance_origin_verified is False


def test_duplicate_key_tuple_fails_closed() -> None:
    registry = trusted_registry()
    registry["keys"].append(copy.deepcopy(registry["keys"][0]))
    result = verify(registry=registry)
    assert result.errors == ("registry_duplicate_key",)


def test_registry_key_id_must_match_public_key_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = trusted_registry()
    registry["keys"][0]["key_id"] = "ed25519-sha256:" + "0" * 64
    monkeypatch.setattr(
        verifier, "PINNED_REGISTRY_SHA256", canonical_sha256(registry)
    )
    result = verify(registry=registry)
    assert result.ok is False
    assert result.acceptance_origin_verified is False
    assert result.errors == ("registry_key_id_public_key_mismatch",)


def test_unreferenced_retired_bad_key_id_invalidates_entire_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = trusted_registry()
    second = copy.deepcopy(registry["keys"][0])
    second["producer_id"] = "fixture-producer-b"
    second["key_id"] = "ed25519-sha256:" + "f" * 64
    second["state"] = "RETIRED"
    registry["keys"].append(second)
    monkeypatch.setattr(
        verifier, "PINNED_REGISTRY_SHA256", canonical_sha256(registry)
    )
    result = verify(registry=registry)
    assert result.ok is False
    assert result.acceptance_origin_verified is False
    assert result.errors == ("registry_key_id_public_key_mismatch",)


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("producer_id", "unknown-producer", "origin_key_not_found"),
        ("key_id", "unknown-key", "origin_key_not_found"),
        ("purpose", "WRONG_PURPOSE", "signature_contract_invalid"),
        ("algorithm", "HMAC-SHA256", "signature_contract_invalid"),
    ],
)
def test_signature_binding_mutations_fail_closed(
    field: str,
    replacement: str,
    error: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin_trusted_registry(monkeypatch)
    signature = trusted_signature()
    signature[field] = replacement
    result = verify(signature=signature)
    assert result.ok is False
    assert result.errors == (error,)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("can_execute", True),
        ("can_trade", True),
        ("capital_permission", "ALLOW"),
        ("deploy_permission", "ALLOW"),
        ("execution_authority", "EXECUTE"),
    ],
)
def test_authority_escalation_is_rejected(field: str, replacement) -> None:
    accepted = accepted_receipt()
    accepted[field] = replacement
    result = verify(accepted=accepted)
    assert result.ok is False
    assert result.errors == ("acceptance_authority_not_safe",)


@pytest.mark.parametrize("field", ["source_count", "observation_count"])
def test_evidence_counts_are_bounded(field: str) -> None:
    accepted = accepted_receipt()
    accepted["ruap_evidence"][field] = verifier.MAX_EVIDENCE_COUNT + 1
    result = verify(accepted=accepted)
    assert result.ok is False
    assert result.errors == ("ruap_evidence_contract_invalid",)


def test_registry_order_is_bound_by_pinned_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = trusted_registry()
    second = copy.deepcopy(registry["keys"][0])
    second["producer_id"] = "fixture-producer-b"
    registry["keys"].append(second)
    monkeypatch.setattr(
        verifier, "PINNED_REGISTRY_SHA256", canonical_sha256(registry)
    )
    reverse = copy.deepcopy(registry)
    reverse["keys"].reverse()
    assert canonical_sha256(registry) != canonical_sha256(reverse)
    result = verify(registry=reverse)
    assert result.errors == ("registry_sha256_mismatch",)


def test_base64_length_rejected_before_decoder(monkeypatch: pytest.MonkeyPatch) -> None:
    def decoder_must_not_run(*args, **kwargs):
        raise AssertionError("decoder called before encoded-length guard")

    monkeypatch.setattr(verifier.base64, "b64decode", decoder_must_not_run)

    with pytest.raises(ValueError, match="public_key_encoding_invalid"):
        verifier._decode_canonical_b64u(
            "A" * 44, expected_len=32, label="public_key"
        )
    with pytest.raises(ValueError, match="signature_encoding_invalid"):
        verifier._decode_canonical_b64u(
            "A" * 87, expected_len=64, label="signature"
        )


def test_oversized_strings_and_field_names_fail_before_canonicalization() -> None:
    signature = trusted_signature()
    signature["signature_b64u"] = "A" * (verifier.MAX_STRING_LEN + 1)
    result = verify(signature=signature)
    assert result.errors == ("string_too_long",)

    signature = trusted_signature()
    long_key = "x" * (verifier.MAX_FIELD_NAME_LEN + 1)
    signature[long_key] = "caller"
    result = verify(signature=signature)
    assert result.errors == ("field_name_too_long",)


def test_unknown_field_error_is_bounded() -> None:
    signature = trusted_signature()
    bounded_key = "x" * verifier.MAX_FIELD_NAME_LEN
    signature[bounded_key] = "caller"
    result = verify(signature=signature)
    assert result.errors == (f"signature_unknown_key:{bounded_key}",)
    assert len(result.errors[0]) <= verifier.MAX_FIELD_NAME_LEN + 32


def test_snapshot_total_node_budget_fails_closed() -> None:
    signature = trusted_signature()
    # Shallow branching exceeds the global copy budget without hitting depth.
    item = {f"k{index}": "x" for index in range(8)}
    signature["extra"] = [copy.deepcopy(item) for _ in range(64)]
    result = verify(signature=signature)
    assert result.errors == ("snapshot_node_budget_exceeded",)


def test_require_valid_returns_preverification_acceptance_snapshot_under_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accepted = accepted_receipt()
    registry = trusted_registry()
    signature = trusted_signature()
    expected = copy.deepcopy(accepted)
    observed: dict[str, object] = {}

    def fake_verify(*, accepted_receipt, key_registry, signature_envelope):
        observed["accepted"] = accepted_receipt
        observed["registry"] = key_registry
        observed["signature"] = signature_envelope
        accepted["source_client"] = "hermes"
        registry["keys"][0]["state"] = "REVOKED"
        signature["producer_id"] = "mutated"
        return verifier.AcceptanceOriginVerification(
            True,
            (),
            True,
            ACCEPTANCE_SHA256,
            TRUSTED_REGISTRY_SHA256,
            "fixture-producer-a",
            TRUSTED_KEY_ID,
        )

    monkeypatch.setattr(
        verifier, "verify_cross_ai_ruap_receipt_acceptance_origin", fake_verify
    )
    returned = verifier.require_valid_cross_ai_ruap_receipt_acceptance_origin(
        accepted_receipt=accepted,
        key_registry=registry,
        signature_envelope=signature,
    )
    assert returned == expected
    assert returned is observed["accepted"]
    assert returned is not accepted
    assert observed["registry"] is not registry
    assert observed["signature"] is not signature
    assert accepted != expected


def test_require_valid_raises_bounded_error() -> None:
    with pytest.raises(ValueError, match="registry_sha256_mismatch") as exc:
        verifier.require_valid_cross_ai_ruap_receipt_acceptance_origin(
            accepted_receipt=accepted_receipt(),
            key_registry=trusted_registry(),
            signature_envelope=trusted_signature(),
        )
    assert len(str(exc.value)) < 256


def test_non_plain_and_unknown_fields_fail_closed() -> None:
    result = verifier.verify_cross_ai_ruap_receipt_acceptance_origin(
        accepted_receipt=[],
        key_registry=trusted_registry(),
        signature_envelope=trusted_signature(),
    )
    assert result.errors == ("acceptance_not_plain_object",)

    signature = trusted_signature()
    signature["manual_attestation"] = "caller"
    result = verify(signature=signature)
    assert result.errors == ("signature_unknown_key:manual_attestation",)


def test_public_api_is_keyword_only_and_exact() -> None:
    for fn in (
        verifier.verify_cross_ai_ruap_receipt_acceptance_origin,
        verifier.require_valid_cross_ai_ruap_receipt_acceptance_origin,
    ):
        signature = inspect.signature(fn)
        assert list(signature.parameters) == [
            "accepted_receipt", "key_registry", "signature_envelope"
        ]
        assert all(
            parameter.kind is inspect.Parameter.KEYWORD_ONLY
            for parameter in signature.parameters.values()
        )


def test_module_has_only_optional_cryptography_and_no_effect_capabilities() -> None:
    tree = ast.parse(inspect.getsource(verifier))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
    assert imported <= {
        "__future__", "base64", "dataclasses", "hashlib", "json", "typing",
        "cryptography",
    }
    assert "continuityos" not in imported

    forbidden = {
        "open", "exec", "eval", "compile", "__import__", "getenv", "system",
        "popen", "run", "Popen", "urlopen", "request", "connect",
    }
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    assert not (forbidden & calls)
