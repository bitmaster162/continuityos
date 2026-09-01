from __future__ import annotations

import ast
import inspect
import json

import pytest

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


def raw_snapshot() -> str:
    return json.dumps(snapshot())


def test_transport_projects_only_bounded_ruap_evidence():
    receipt = cart.build_cross_ai_ruap_transport_receipt(
        source_client="claude",
        target_client="cursor",
        ruap_snapshot=raw_snapshot(),
    )

    assert receipt["schema"] == "continuityos.cross_ai_ruap_transport/v1"
    assert receipt["mode"] == "EVIDENCE_ONLY"
    assert receipt["transport_mode"] == "RUAP_EVIDENCE_ONLY"
    assert receipt["context_transport"] == "RUAP_EVIDENCE_ONLY"
    assert receipt["ruap_integration"] == "BOUNDED_EVIDENCE_PROJECTION"
    assert receipt["source_client"] == "claude"
    assert receipt["target_client"] == "cursor"
    assert receipt["execution_authority"] == "NONE"
    assert receipt["can_execute"] is False
    assert receipt["can_trade"] is False
    assert receipt["capital_permission"] == "DENY"
    assert receipt["deploy_permission"] == "DENY"
    assert all(value is False for value in receipt["effects"].values())

    evidence = receipt["ruap_evidence"]
    assert evidence["schema"] == "ruap.snapshot/v1"
    assert evidence["snapshot_sha256"]
    assert evidence["source_count"] == 1
    assert evidence["observation_count"] == 1
    assert evidence["freshness_required"] is True
    assert evidence["authority_ceiling"] == "OBSERVE_ONLY"
    assert evidence["authority_class"] == "EVIDENCE_ONLY"
    assert evidence["raw_snapshot_exposed"] is False
    assert evidence["raw_sources_exposed"] is False
    assert evidence["raw_observations_exposed"] is False


def test_transport_never_echoes_caller_controlled_ruap_text():
    receipt = cart.build_cross_ai_ruap_transport_receipt(
        source_client="claude",
        target_client="cursor",
        ruap_snapshot=raw_snapshot(),
    )
    public = json.dumps(receipt, sort_keys=True)

    for marker in (
        "GENERATED_AT_PRIVATE_MARKER",
        "LOCATOR_PRIVATE_MARKER",
        "OBSERVED_AT_PRIVATE_MARKER",
        "SUBJECT_PRIVATE_MARKER",
        "CLAIM_PRIVATE_MARKER",
    ):
        assert marker not in public


def test_transport_fails_closed_on_ruap_authority_escalation():
    value = snapshot()
    value["can_execute"] = True

    with pytest.raises(ValueError, match="invalid RUAP snapshot"):
        cart.build_cross_ai_ruap_transport_receipt(
            source_client="claude",
            target_client="cursor",
            ruap_snapshot=json.dumps(value),
        )


def test_transport_requires_distinct_allowlisted_clients():
    for source, target in (
        ("claude", "cursor"),
        ("cursor", "hermes"),
        ("hermes", "generic-mcp"),
    ):
        receipt = cart.build_cross_ai_ruap_transport_receipt(
            source_client=source,
            target_client=target,
            ruap_snapshot=raw_snapshot(),
        )
        assert receipt["source_client"] != receipt["target_client"]

    with pytest.raises(ValueError, match="CLIENTS_MUST_BE_DISTINCT"):
        cart.build_cross_ai_ruap_transport_receipt(
            source_client="claude",
            target_client="claude",
            ruap_snapshot=raw_snapshot(),
        )
    with pytest.raises(ValueError, match="SOURCE_CLIENT_UNSUPPORTED"):
        cart.build_cross_ai_ruap_transport_receipt(
            source_client="unknown",
            target_client="cursor",
            ruap_snapshot=raw_snapshot(),
        )
    with pytest.raises(ValueError, match="TARGET_CLIENT_UNSUPPORTED"):
        cart.build_cross_ai_ruap_transport_receipt(
            source_client="claude",
            target_client="unknown",
            ruap_snapshot=raw_snapshot(),
        )


def test_transport_receipt_is_deterministic_and_snapshot_identity_bearing():
    first = cart.canonical_cross_ai_ruap_transport_json(
        source_client="claude",
        target_client="cursor",
        ruap_snapshot=raw_snapshot(),
    )
    second = cart.canonical_cross_ai_ruap_transport_json(
        source_client="claude",
        target_client="cursor",
        ruap_snapshot=raw_snapshot(),
    )

    changed = snapshot()
    changed["observations"][0]["claim"] = "CHANGED_PRIVATE_MARKER"
    third = cart.canonical_cross_ai_ruap_transport_json(
        source_client="claude",
        target_client="cursor",
        ruap_snapshot=json.dumps(changed),
    )

    assert first == second
    assert json.loads(first)["transport_id"].startswith("xrt_")
    assert json.loads(first)["transport_id"] != json.loads(third)["transport_id"]


def test_public_surface_accepts_no_provider_secret_connector_or_runtime_inputs():
    parameters = inspect.signature(cart.build_cross_ai_ruap_transport_receipt).parameters
    assert tuple(parameters) == ("source_client", "target_client", "ruap_snapshot")
    for forbidden in (
        "provider",
        "secret",
        "token",
        "credential",
        "connector",
        "runtime",
        "pointer",
        "memory",
        "command",
    ):
        assert forbidden not in parameters


def test_transport_module_has_only_pure_ruap_capability_imports():
    source = inspect.getsource(cart)
    tree = ast.parse(source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")

    assert imports <= {
        "__future__",
        "hashlib",
        "json",
        "typing",
        "ruap_portability",
    }
    for token in (
        "connector_preview",
        "connect.py",
        "vault_secret_reference",
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
