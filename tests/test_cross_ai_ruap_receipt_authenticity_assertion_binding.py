from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json

import pytest

import continuityos.cross_ai_ruap_receipt_acceptance as cara
import continuityos.cross_ai_ruap_receipt_authenticity_assertion_binding as caab
import continuityos.cross_ai_ruap_transport as cart


def snapshot() -> dict:
    return {
        "schema": "ruap.snapshot/v1",
        "generated_at": "GENERATED_AT_PRIVATE_MARKER",
        "authority_ceiling": "OBSERVE_ONLY",
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "sources": [
            {
                "id": "s1",
                "provider": "github",
                "locator": "LOCATOR_PRIVATE_MARKER",
                "observed_at": "OBSERVED_AT_PRIVATE_MARKER",
            }
        ],
        "observations": [
            {
                "subject": "SUBJECT_PRIVATE_MARKER",
                "claim": "CLAIM_PRIVATE_MARKER",
                "class": "PROVIDER_READBACK",
                "source_id": "s1",
                "freshness_required_before_effect": True,
            }
        ],
    }


def accepted_receipt() -> dict:
    transport = cart.build_cross_ai_ruap_transport_receipt(
        source_client="claude",
        target_client="cursor",
        ruap_snapshot=json.dumps(snapshot()),
    )
    return cara.accept_cross_ai_ruap_transport_receipt(transport)


def external_assertion(accepted: dict) -> dict:
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
            "provenance_claimed": True,
            "signer_identity_claimed": True,
        },
    }


def canonical_sha256(value: dict) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def test_binding_projects_only_bounded_target_and_claim_metadata():
    accepted = accepted_receipt()
    assertion = external_assertion(accepted)

    binding = caab.bind_cross_ai_ruap_receipt_authenticity_assertion(
        accepted_receipt=accepted,
        external_assertion=assertion,
    )

    assert binding == {
        "schema": (
            "continuityos.cross_ai_ruap_receipt_"
            "authenticity_assertion_binding/v1"
        ),
        "mode": "EVIDENCE_ONLY",
        "binding_class": "EXTERNAL_ASSERTION_BINDING_ONLY",
        "transport_id": accepted["transport_id"],
        "source_client": "claude",
        "target_client": "cursor",
        "ruap_snapshot_sha256": accepted["ruap_evidence"]["snapshot_sha256"],
        "acceptance_sha256": canonical_sha256(accepted),
        "external_assertion": {
            "schema": (
                "continuityos.cross_ai_ruap_external_"
                "authenticity_assertion/v1"
            ),
            "assertion_method": "DETACHED_SIGNATURE_EVIDENCE",
            "assertion_sha256": canonical_sha256(assertion),
            "claims": {
                "authenticity_claimed": True,
                "provenance_claimed": True,
                "signer_identity_claimed": True,
            },
        },
        "verification": {
            "acceptance_shape_verified": True,
            "assertion_shape_verified": True,
            "transport_binding_verified": True,
            "client_binding_verified": True,
            "ruap_evidence_binding_verified": True,
            "assertion_digest_bound": True,
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


def test_binding_is_deterministic_detached_and_does_not_mutate_inputs():
    accepted = accepted_receipt()
    assertion = external_assertion(accepted)
    accepted_before = copy.deepcopy(accepted)
    assertion_before = copy.deepcopy(assertion)

    first = caab.bind_cross_ai_ruap_receipt_authenticity_assertion(
        accepted_receipt=accepted,
        external_assertion=assertion,
    )
    second = caab.bind_cross_ai_ruap_receipt_authenticity_assertion(
        accepted_receipt=accepted,
        external_assertion=assertion,
    )

    assert first == second
    assert accepted == accepted_before
    assert assertion == assertion_before

    assertion["claims"]["authenticity_claimed"] = False
    accepted["ruap_evidence"]["snapshot_sha256"] = "0" * 64

    assert first["external_assertion"]["claims"]["authenticity_claimed"] is True
    assert first["ruap_snapshot_sha256"] != "0" * 64


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("transport_id", "xrt_" + ("0" * 64)),
        ("source_client", "hermes"),
        ("target_client", "generic-mcp"),
        ("ruap_snapshot_sha256", "0" * 64),
    ],
)
def test_binding_fails_closed_on_assertion_target_mismatch(field, replacement):
    accepted = accepted_receipt()
    assertion = external_assertion(accepted)
    assertion[field] = replacement

    with pytest.raises(ValueError, match="assertion_target_mismatch"):
        caab.bind_cross_ai_ruap_receipt_authenticity_assertion(
            accepted_receipt=accepted,
            external_assertion=assertion,
        )


def test_binding_rejects_unsupported_assertion_method():
    accepted = accepted_receipt()
    assertion = external_assertion(accepted)
    assertion["assertion_method"] = "CALLER_DEFINED_METHOD"

    with pytest.raises(ValueError, match="assertion_contract"):
        caab.bind_cross_ai_ruap_receipt_authenticity_assertion(
            accepted_receipt=accepted,
            external_assertion=assertion,
        )


@pytest.mark.parametrize(
    "claims",
    [
        {
            "authenticity_claimed": False,
            "provenance_claimed": False,
            "signer_identity_claimed": False,
        },
        {
            "authenticity_claimed": 1,
            "provenance_claimed": False,
            "signer_identity_claimed": False,
        },
    ],
)
def test_binding_rejects_empty_or_non_boolean_claims(claims):
    accepted = accepted_receipt()
    assertion = external_assertion(accepted)
    assertion["claims"] = claims

    with pytest.raises(ValueError, match="no_claim|claim_type"):
        caab.bind_cross_ai_ruap_receipt_authenticity_assertion(
            accepted_receipt=accepted,
            external_assertion=assertion,
        )


def test_binding_rejects_raw_signature_or_identity_fields():
    accepted = accepted_receipt()
    assertion = external_assertion(accepted)
    assertion["signature"] = "RAW_SIGNATURE_PRIVATE_MARKER"

    with pytest.raises(ValueError, match="external_assertion_shape"):
        caab.bind_cross_ai_ruap_receipt_authenticity_assertion(
            accepted_receipt=accepted,
            external_assertion=assertion,
        )

    assertion = external_assertion(accepted)
    assertion["signer_identity"] = "CALLER_CONTROLLED_IDENTITY_PRIVATE_MARKER"
    with pytest.raises(ValueError, match="external_assertion_shape"):
        caab.bind_cross_ai_ruap_receipt_authenticity_assertion(
            accepted_receipt=accepted,
            external_assertion=assertion,
        )


@pytest.mark.parametrize(
    "mutator,match",
    [
        (
            lambda accepted: accepted.__setitem__("can_execute", True),
            "acceptance_authority",
        ),
        (
            lambda accepted: accepted["verification"].__setitem__(
                "authenticity_verified", True
            ),
            "acceptance_verification",
        ),
        (
            lambda accepted: accepted["ruap_evidence"].__setitem__(
                "authority_ceiling", "EXECUTE"
            ),
            "ruap_evidence_contract",
        ),
        (
            lambda accepted: accepted["ruap_evidence"].__setitem__(
                "schema", "other.snapshot/v1"
            ),
            "ruap_evidence_contract",
        ),
    ],
)
def test_binding_rejects_unsafe_or_forged_acceptance(mutator, match):
    accepted = accepted_receipt()
    assertion = external_assertion(accepted)
    mutator(accepted)

    with pytest.raises(ValueError, match=match):
        caab.bind_cross_ai_ruap_receipt_authenticity_assertion(
            accepted_receipt=accepted,
            external_assertion=assertion,
        )


def test_binding_never_promotes_external_claims_to_verification():
    accepted = accepted_receipt()
    assertion = external_assertion(accepted)

    binding = caab.bind_cross_ai_ruap_receipt_authenticity_assertion(
        accepted_receipt=accepted,
        external_assertion=assertion,
    )

    assert binding["external_assertion"]["claims"] == {
        "authenticity_claimed": True,
        "provenance_claimed": True,
        "signer_identity_claimed": True,
    }
    assert binding["verification"]["authenticity_verified"] is False
    assert binding["verification"]["provenance_verified"] is False
    assert binding["verification"]["signer_identity_verified"] is False
    assert binding["verification"]["current_truth_promoted"] is False


def test_binding_public_surface_is_exactly_two_keyword_only_inputs():
    parameters = inspect.signature(
        caab.bind_cross_ai_ruap_receipt_authenticity_assertion
    ).parameters
    assert tuple(parameters) == ("accepted_receipt", "external_assertion")
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in parameters.values()
    )


def test_binding_module_capabilities_are_stdlib_only_and_no_io():
    source = inspect.getsource(caab)
    tree = ast.parse(source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")

    assert imports <= {"__future__", "hashlib", "json", "typing"}

    for token in (
        "ruap_portability",
        "vault_secret_reference",
        "connector_preview",
        "os.environ",
        "os.getenv",
        "subprocess.",
        "socket.",
        "requests.",
        "urllib.",
        "pathlib.",
        "open(",
    ):
        assert token not in source
