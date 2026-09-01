from __future__ import annotations

import ast
import inspect
import json

import pytest

import continuityos.cross_ai_demo as cad


def test_synthetic_cross_ai_demo_preserves_zero_effect_governance():
    receipt = cad.build_cross_ai_demo_contract(
        source_client="claude",
        target_client="cursor",
    )

    assert receipt["schema"] == "continuityos.cross_ai_demo/v1"
    assert receipt["mode"] == "DEMO_ONLY"
    assert receipt["transport_mode"] == "SYNTHETIC_ONLY"
    assert receipt["source_client"] == "claude"
    assert receipt["target_client"] == "cursor"
    assert receipt["purpose_id"] == "cross_ai_demo"
    assert receipt["context_transport"] == "NOT_IMPLEMENTED"
    assert receipt["ruap_integration"] == "OUT_OF_SCOPE_PRE_MERGE"
    assert receipt["execution_authority"] == "NONE"
    assert receipt["can_execute"] is False
    assert receipt["can_trade"] is False
    assert receipt["capital_permission"] == "DENY"
    assert all(value is False for value in receipt["effects"].values())


def test_demo_uses_merged_p6_cross_ai_metadata_reference_without_binding():
    receipt = cad.build_cross_ai_demo_contract(
        source_client="claude",
        target_client="cursor",
    )
    reference = receipt["secret_reference"]

    assert reference["reference_id"].startswith("vsr_")
    assert reference["reference_id_policy"] == "OPAQUE_STABLE_BOUNDED_METADATA_SHA256"
    assert reference["purpose_id"] == "cross_ai_demo"
    assert reference["purpose_id_policy"] == "BOUNDED_ALLOWLIST"
    assert reference["provider"] == "unbound"
    assert reference["secret_kind"] == "credential"
    assert reference["required"] is False
    assert reference["binding_present"] is False
    assert reference["binding_authorized"] is False
    assert reference["live_secret_access_available"] is False


def test_demo_receipt_is_deterministic_and_direction_is_identity_bearing():
    first = cad.canonical_cross_ai_demo_json(
        source_client="claude",
        target_client="cursor",
    )
    second = cad.canonical_cross_ai_demo_json(
        source_client="claude",
        target_client="cursor",
    )
    reverse = cad.canonical_cross_ai_demo_json(
        source_client="cursor",
        target_client="claude",
    )

    assert first == second
    assert json.loads(first)["demo_id"].startswith("xad_")
    assert json.loads(first)["demo_id"] != json.loads(reverse)["demo_id"]


def test_demo_requires_two_distinct_allowlisted_ai_client_identities():
    for source, target in (
        ("claude", "cursor"),
        ("cursor", "hermes"),
        ("hermes", "generic-mcp"),
    ):
        receipt = cad.build_cross_ai_demo_contract(
            source_client=source,
            target_client=target,
        )
        assert receipt["source_client"] != receipt["target_client"]

    with pytest.raises(ValueError, match="CLIENTS_MUST_BE_DISTINCT"):
        cad.build_cross_ai_demo_contract(source_client="claude", target_client="claude")
    with pytest.raises(ValueError, match="SOURCE_CLIENT_UNSUPPORTED"):
        cad.build_cross_ai_demo_contract(source_client="unknown", target_client="cursor")
    with pytest.raises(ValueError, match="TARGET_CLIENT_UNSUPPORTED"):
        cad.build_cross_ai_demo_contract(source_client="claude", target_client="unknown")
    with pytest.raises(ValueError, match="SOURCE_CLIENT_UNSUPPORTED"):
        cad.build_cross_ai_demo_contract(source_client=object(), target_client="cursor")


def test_public_build_surface_accepts_only_client_identities():
    parameters = inspect.signature(cad.build_cross_ai_demo_contract).parameters
    assert tuple(parameters) == ("source_client", "target_client")
    assert "prompt" not in parameters
    assert "secret" not in parameters
    assert "token" not in parameters
    assert "locator" not in parameters
    assert "credential" not in parameters


def test_production_module_has_no_ruap_or_effect_capability_imports():
    source = inspect.getsource(cad)
    tree = ast.parse(source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")

    assert "ruap_portability" not in source
    assert imports <= {
        "__future__",
        "hashlib",
        "json",
        "typing",
        "vault_secret_reference",
    }
    for token in (
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
