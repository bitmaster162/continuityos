from __future__ import annotations

import ast
import copy
import inspect
import json

import pytest

import continuityos.cross_ai_ruap_receipt_acceptance as cara
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


def receipt() -> dict:
    return cart.build_cross_ai_ruap_transport_receipt(
        source_client="claude",
        target_client="cursor",
        ruap_snapshot=json.dumps(snapshot()),
    )


def test_acceptance_projects_only_verified_bounded_metadata():
    value = receipt()
    accepted = cara.accept_cross_ai_ruap_transport_receipt(value)

    assert accepted == {
        "schema": "continuityos.cross_ai_ruap_receipt_acceptance/v1",
        "mode": "EVIDENCE_ONLY",
        "acceptance_class": "STRUCTURAL_SELF_CONSISTENCY_ONLY",
        "transport_id": value["transport_id"],
        "source_client": "claude",
        "target_client": "cursor",
        "ruap_evidence": {
            "schema": "ruap.snapshot/v1",
            "snapshot_sha256": value["ruap_evidence"]["snapshot_sha256"],
            "source_count": 1,
            "observation_count": 1,
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


def test_acceptance_is_deterministic_and_does_not_mutate_input():
    value = receipt()
    before = copy.deepcopy(value)

    first = cara.accept_cross_ai_ruap_transport_receipt(value)
    second = cara.accept_cross_ai_ruap_transport_receipt(value)

    assert first == second
    assert value == before


def test_acceptance_never_echoes_raw_or_caller_controlled_ruap_text():
    accepted = cara.accept_cross_ai_ruap_transport_receipt(receipt())
    public = json.dumps(accepted, sort_keys=True)

    for marker in (
        "GENERATED_AT_PRIVATE_MARKER",
        "LOCATOR_PRIVATE_MARKER",
        "OBSERVED_AT_PRIVATE_MARKER",
        "SUBJECT_PRIVATE_MARKER",
        "CLAIM_PRIVATE_MARKER",
    ):
        assert marker not in public

    assert "raw_snapshot" not in public
    assert "raw_sources" not in public
    assert "raw_observations" not in public


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.__setitem__("can_execute", True),
        lambda value: value["effects"].__setitem__("network_effect", True),
        lambda value: value.__setitem__("transport_id", "xrt_" + ("0" * 64)),
        lambda value: value.__setitem__("prompt", "CALLER_CONTROLLED_PRIVATE_MARKER"),
    ],
)
def test_acceptance_fails_closed_when_verifier_rejects(mutator):
    value = copy.deepcopy(receipt())
    mutator(value)

    with pytest.raises(ValueError, match="invalid Cross-AI RUAP transport receipt"):
        cara.accept_cross_ai_ruap_transport_receipt(value)


def test_acceptance_invokes_standalone_verifier_before_projection(monkeypatch):
    calls = []

    def fake_require(value):
        calls.append(value)
        raise ValueError("VERIFIER_SENTINEL")

    monkeypatch.setattr(
        cara,
        "require_valid_cross_ai_ruap_transport_receipt",
        fake_require,
    )

    supplied = {"untrusted": True}
    with pytest.raises(ValueError, match="VERIFIER_SENTINEL"):
        cara.accept_cross_ai_ruap_transport_receipt(supplied)

    assert calls == [supplied]


def test_acceptance_public_surface_accepts_only_supplied_receipt():
    parameters = inspect.signature(cara.accept_cross_ai_ruap_transport_receipt).parameters
    assert tuple(parameters) == ("receipt",)


def test_acceptance_module_has_only_verifier_capability_import():
    source = inspect.getsource(cara)
    tree = ast.parse(source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")

    assert imports <= {
        "__future__",
        "typing",
        "cross_ai_ruap_transport_verifier",
    }
    assert "require_valid_cross_ai_ruap_transport_receipt" in source

    for token in (
        "import continuityos.cross_ai_ruap_transport as",
        "ruap_portability",
        "vault_secret_reference",
        "connector_preview",
        "connect.py",
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
