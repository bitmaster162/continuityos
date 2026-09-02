from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json

import pytest

import continuityos.cross_ai_ruap_receipt_authenticity_assertion_binding as producer
import continuityos.cross_ai_ruap_receipt_authenticity_assertion_binding_verifier as verifier


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


def external_assertion() -> dict:
    accepted = accepted_receipt()
    return {
        "schema": "continuityos.cross_ai_ruap_external_authenticity_assertion/v1",
        "mode": "EVIDENCE_ONLY",
        "assertion_method": "DETACHED_SIGNATURE_EVIDENCE",
        "transport_id": accepted["transport_id"],
        "source_client": accepted["source_client"],
        "target_client": accepted["target_client"],
        "ruap_snapshot_sha256": accepted["ruap_evidence"]["snapshot_sha256"],
        "claims": {
            "authenticity_claimed": True,
            "provenance_claimed": False,
            "signer_identity_claimed": False,
        },
    }


def binding_result() -> dict:
    return producer.bind_cross_ai_ruap_receipt_authenticity_assertion(
        accepted_receipt=accepted_receipt(),
        external_assertion=external_assertion(),
    )


def canonical_sha256(value: dict) -> str:
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def verify(binding: dict, accepted: dict | None = None, assertion: dict | None = None):
    return verifier.verify_cross_ai_ruap_receipt_authenticity_assertion_binding(
        binding_result=binding,
        accepted_receipt=accepted if accepted is not None else accepted_receipt(),
        external_assertion=assertion if assertion is not None else external_assertion(),
    )


def test_valid_binding_recomputes_both_digests() -> None:
    accepted = accepted_receipt()
    assertion = external_assertion()
    binding = producer.bind_cross_ai_ruap_receipt_authenticity_assertion(
        accepted_receipt=accepted, external_assertion=assertion
    )
    result = verify(binding, accepted, assertion)
    assert result.ok is True
    assert result.errors == ()
    assert result.expected_acceptance_sha256 == canonical_sha256(accepted)
    assert result.expected_assertion_sha256 == canonical_sha256(assertion)


def test_require_valid_returns_detached_binding_without_mutation() -> None:
    accepted = accepted_receipt()
    assertion = external_assertion()
    binding = producer.bind_cross_ai_ruap_receipt_authenticity_assertion(
        accepted_receipt=accepted, external_assertion=assertion
    )
    before = (copy.deepcopy(accepted), copy.deepcopy(assertion), copy.deepcopy(binding))
    returned = verifier.require_valid_cross_ai_ruap_receipt_authenticity_assertion_binding(
        binding_result=binding,
        accepted_receipt=accepted,
        external_assertion=assertion,
    )
    assert returned == binding and returned is not binding
    assert returned["external_assertion"] is not binding["external_assertion"]
    assert (accepted, assertion, binding) == before


@pytest.mark.parametrize(
    ("path", "replacement", "error"),
    [
        (("acceptance_sha256",), "0" * 64, "acceptance_sha256_mismatch"),
        (("external_assertion", "assertion_sha256"), "0" * 64, "assertion_sha256_mismatch"),
        (("transport_id",), "xrt_" + "9" * 64, "binding_transport_id_mismatch"),
        (("source_client",), "hermes", "binding_client_mismatch"),
        (("ruap_snapshot_sha256",), "9" * 64, "binding_ruap_snapshot_sha256_mismatch"),
    ],
)
def test_binding_tampering_fails_closed(path, replacement, error) -> None:
    binding = binding_result()
    target = binding
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    result = verify(binding)
    assert result.ok is False
    assert result.errors == (error,)


def test_acceptance_tampering_breaks_digest_binding() -> None:
    accepted = accepted_receipt()
    assertion = external_assertion()
    binding = producer.bind_cross_ai_ruap_receipt_authenticity_assertion(
        accepted_receipt=accepted, external_assertion=assertion
    )
    accepted["ruap_evidence"]["observation_count"] += 1
    result = verify(binding, accepted, assertion)
    assert result.ok is False
    assert result.errors == ("acceptance_sha256_mismatch",)


def test_assertion_tampering_breaks_digest_binding() -> None:
    assertion = external_assertion()
    binding = binding_result()
    assertion["claims"]["provenance_claimed"] = True
    result = verify(binding, assertion=assertion)
    assert result.ok is False
    assert result.errors == ("assertion_sha256_mismatch",)


def test_assertion_target_mismatch_fails_closed() -> None:
    assertion = external_assertion()
    assertion["target_client"] = "hermes"
    result = verify(binding_result(), assertion=assertion)
    assert result.ok is False
    assert result.errors == ("assertion_target_mismatch",)


@pytest.mark.parametrize("container", ["accepted", "binding"])
def test_effect_authority_escalation_fails_closed(container: str) -> None:
    accepted = accepted_receipt()
    binding = binding_result()
    if container == "accepted":
        accepted["can_execute"] = True
        result = verify(binding, accepted=accepted)
        assert result.errors == ("acceptance_authority_not_safe",)
    else:
        binding["can_execute"] = True
        result = verify(binding)
        assert result.errors == ("binding_authority_not_safe",)
    assert result.ok is False


@pytest.mark.parametrize(
    "key",
    [
        "acceptance_origin_verified",
        "authenticity_verified",
        "provenance_verified",
        "signer_identity_verified",
        "current_truth_promoted",
    ],
)
def test_binding_cannot_promote_trust(key: str) -> None:
    binding = binding_result()
    binding["verification"][key] = True
    result = verify(binding)
    assert result.ok is False
    assert result.errors == ("binding_verification_not_safe",)


def test_raw_signature_and_signer_identity_fields_are_rejected() -> None:
    assertion = external_assertion()
    assertion["signature"] = "raw"
    result = verify(binding_result(), assertion=assertion)
    assert result.errors == ("assertion_unknown_key:signature",)

    binding = binding_result()
    binding["external_assertion"]["signer_identity"] = "caller"
    result = verify(binding)
    assert result.errors == ("projected_assertion_unknown_key:signer_identity",)


def test_fabricated_safe_shaped_acceptance_remains_origin_unverified() -> None:
    accepted = accepted_receipt()
    assertion = external_assertion()
    binding = producer.bind_cross_ai_ruap_receipt_authenticity_assertion(
        accepted_receipt=accepted, external_assertion=assertion
    )
    result = verify(binding, accepted, assertion)
    assert result.ok is True
    assert binding["acceptance_input_class"] == "CALLER_SUPPLIED_ACCEPTANCE_SHAPED_EVIDENCE"
    assert binding["verification"]["acceptance_origin_verified"] is False
    assert binding["verification"]["authenticity_verified"] is False
    assert binding["verification"]["provenance_verified"] is False
    assert binding["verification"]["signer_identity_verified"] is False
    assert binding["verification"]["current_truth_promoted"] is False


def test_non_plain_and_nested_inputs_fail_closed() -> None:
    result = verifier.verify_cross_ai_ruap_receipt_authenticity_assertion_binding(
        binding_result=[],
        accepted_receipt=accepted_receipt(),
        external_assertion=external_assertion(),
    )
    assert result.errors == ("non_plain_value",)

    binding = binding_result()
    binding["external_assertion"]["claims"]["extra"] = {"nested": {"too": "deep"}}
    result = verify(binding)
    assert result.errors == ("nested_too_deep",)


def test_public_api_is_keyword_only_and_exact() -> None:
    for fn in (
        verifier.verify_cross_ai_ruap_receipt_authenticity_assertion_binding,
        verifier.require_valid_cross_ai_ruap_receipt_authenticity_assertion_binding,
    ):
        signature = inspect.signature(fn)
        assert list(signature.parameters) == [
            "binding_result", "accepted_receipt", "external_assertion"
        ]
        assert all(
            parameter.kind is inspect.Parameter.KEYWORD_ONLY
            for parameter in signature.parameters.values()
        )


def test_module_is_stdlib_only_and_has_no_io_capabilities() -> None:
    tree = ast.parse(inspect.getsource(verifier))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
    assert imported <= {"__future__", "dataclasses", "hashlib", "json", "typing"}
    assert "continuityos" not in imported

    forbidden = {
        "open", "exec", "eval", "compile", "__import__", "getenv", "system",
        "popen", "run", "Popen", "urlopen", "request", "connect",
    }
    calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    assert not (forbidden & calls)


def test_require_valid_raises_bounded_error() -> None:
    binding = binding_result()
    binding["acceptance_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="acceptance_sha256_mismatch"):
        verifier.require_valid_cross_ai_ruap_receipt_authenticity_assertion_binding(
            binding_result=binding,
            accepted_receipt=accepted_receipt(),
            external_assertion=external_assertion(),
        )
