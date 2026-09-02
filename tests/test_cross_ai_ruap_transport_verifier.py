from __future__ import annotations

import ast
import copy
import inspect
import json

import pytest

import continuityos.cross_ai_ruap_transport as cart
import continuityos.cross_ai_ruap_transport_verifier as cav


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


def test_verifier_accepts_exact_transport_receipt_and_recomputes_identity():
    value = receipt()
    result = cav.verify_cross_ai_ruap_transport_receipt(value)

    assert result.ok is True
    assert result.errors == ()
    assert result.expected_transport_id == value["transport_id"]
    assert cav.require_valid_cross_ai_ruap_transport_receipt(value) is value


@pytest.mark.parametrize(
    ("path", "unsafe"),
    [
        (("execution_authority",), "EXECUTE"),
        (("can_execute",), True),
        (("can_trade",), True),
        (("capital_permission",), "ALLOW"),
        (("deploy_permission",), "ALLOW"),
        (("ruap_evidence", "authority_ceiling"), "EXECUTE"),
        (("ruap_evidence", "authority_class"), "EXECUTION_AUTHORITY"),
        (("ruap_evidence", "raw_snapshot_exposed"), True),
        (("ruap_evidence", "raw_sources_exposed"), True),
        (("ruap_evidence", "raw_observations_exposed"), True),
        (("effects", "network_effect"), True),
        (("effects", "credential_access"), True),
        (("effects", "filesystem_read"), True),
        (("effects", "runtime_mutation"), True),
        (("effects", "deployment"), True),
        (("effects", "trading_effect"), True),
        (("effects", "capital_effect"), True),
    ],
)
def test_verifier_fails_closed_on_authority_raw_exposure_or_effect_escalation(path, unsafe):
    value = copy.deepcopy(receipt())
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = unsafe

    result = cav.verify_cross_ai_ruap_transport_receipt(value)
    assert result.ok is False
    with pytest.raises(ValueError, match="invalid Cross-AI RUAP transport receipt"):
        cav.require_valid_cross_ai_ruap_transport_receipt(value)


@pytest.mark.parametrize(
    ("container_path", "extra_key"),
    [
        ((), "prompt"),
        ((), "raw_snapshot"),
        (("ruap_evidence",), "claim"),
        (("ruap_evidence",), "locator"),
        (("effects",), "shell_effect"),
    ],
)
def test_verifier_rejects_unknown_or_raw_public_fields(container_path, extra_key):
    value = copy.deepcopy(receipt())
    target = value
    for key in container_path:
        target = target[key]
    target[extra_key] = "CALLER_CONTROLLED_PRIVATE_MARKER"

    result = cav.verify_cross_ai_ruap_transport_receipt(value)
    assert result.ok is False
    assert any("unknown_key" in error for error in result.errors)


def test_verifier_rejects_missing_fields_wrong_types_and_client_identity_drift():
    mutations = []

    missing = copy.deepcopy(receipt())
    missing.pop("effects")
    mutations.append(missing)

    wrong_root_type = copy.deepcopy(receipt())
    wrong_root_type["can_execute"] = 0
    mutations.append(wrong_root_type)

    wrong_count_type = copy.deepcopy(receipt())
    wrong_count_type["ruap_evidence"]["source_count"] = False
    mutations.append(wrong_count_type)

    bad_digest = copy.deepcopy(receipt())
    bad_digest["ruap_evidence"]["snapshot_sha256"] = "A" * 64
    mutations.append(bad_digest)

    unsupported = copy.deepcopy(receipt())
    unsupported["source_client"] = "unknown"
    mutations.append(unsupported)

    same_client = copy.deepcopy(receipt())
    same_client["target_client"] = same_client["source_client"]
    mutations.append(same_client)

    non_plain = tuple(receipt().items())
    mutations.append(non_plain)

    for value in mutations:
        assert cav.verify_cross_ai_ruap_transport_receipt(value).ok is False


def test_verifier_detects_transport_id_tampering_and_core_tampering():
    value = receipt()

    bad_id = copy.deepcopy(value)
    bad_id["transport_id"] = "xrt_" + ("0" * 64)
    result = cav.verify_cross_ai_ruap_transport_receipt(bad_id)
    assert result.ok is False
    assert "transport_id_mismatch" in result.errors

    changed_count = copy.deepcopy(value)
    changed_count["ruap_evidence"]["observation_count"] += 1
    result = cav.verify_cross_ai_ruap_transport_receipt(changed_count)
    assert result.ok is False
    assert "transport_id_mismatch" in result.errors


def test_verifier_public_surface_accepts_only_supplied_receipt():
    parameters = inspect.signature(cav.verify_cross_ai_ruap_transport_receipt).parameters
    assert tuple(parameters) == ("receipt",)

    required_parameters = inspect.signature(
        cav.require_valid_cross_ai_ruap_transport_receipt
    ).parameters
    assert tuple(required_parameters) == ("receipt",)


def test_verifier_module_is_pure_and_has_no_effect_capability_imports():
    source = inspect.getsource(cav)
    tree = ast.parse(source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")

    assert imports <= {
        "__future__",
        "dataclasses",
        "hashlib",
        "json",
        "typing",
    }
    for token in (
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
