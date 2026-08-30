from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

import continuityos.vault_secret_reference as vsr


def test_unbound_reference_is_metadata_only_and_preserves_none_false_authority():
    receipt = vsr.build_secret_reference(
        reference_id="openai.primary",
        provider="unbound",
        purpose_id="cross_ai_demo",
        secret_kind="api_key",
    )

    assert receipt["schema"] == "continuityos.vault_secret_reference/v1"
    assert receipt["mode"] == "METADATA_ONLY"
    assert receipt["provider"] == "unbound"
    assert "locator" not in receipt
    assert receipt["binding_present"] is False
    assert receipt["binding_authorized"] is False
    assert receipt["readiness"] == "PROVIDER_UNBOUND"
    assert receipt["secret_value_present"] is False
    assert receipt["live_secret_access_available"] is False
    assert receipt["execution_authority"] == "NONE"
    assert receipt["can_execute"] is False
    assert receipt["can_trade"] is False
    assert receipt["capital_permission"] == "DENY"
    assert all(value is False for value in receipt["effects"].values())


def test_declared_environment_provider_class_never_reads_or_binds_environment(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "super-secret-value-that-must-never-be-read")

    receipt = vsr.build_secret_reference(
        reference_id="openai.primary",
        provider="environment",
        purpose_id="cross_ai_demo",
        secret_kind="api_key",
    )

    encoded = json.dumps(receipt, sort_keys=True)
    assert receipt["readiness"] == "PROVIDER_CLASS_DECLARED_BINDING_NOT_AUTHORIZED"
    assert receipt["binding_present"] is False
    assert receipt["binding_authorized"] is False
    assert receipt["effects"]["secret_binding_accepted"] is False
    assert receipt["effects"]["environment_read"] is False
    assert "locator" not in receipt
    assert "OPENAI_API_KEY" not in encoded
    assert "super-secret-value-that-must-never-be-read" not in encoded


@pytest.mark.parametrize(
    "field",
    [
        "secret",
        "secret_value",
        "value",
        "token_value",
        "password_value",
        "private_key_value",
        "api_key_value",
        "credential_value",
        "plaintext",
        "ciphertext",
    ],
)
def test_secret_bearing_fields_are_rejected(field):
    payload = {
        "reference_id": "service.primary",
        "purpose_id": "connector_auth",
        field: "definitely-not-metadata",
    }
    with pytest.raises(vsr.SecretReferenceError, match="SECRET_VALUE_FIELD_FORBIDDEN"):
        vsr.validate_secret_reference(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("locator", "OPENAI_API_KEY"),
        ("locator", "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"),
        ("locator", "sk" + "-proj-" + "abcdefghijklmnopqrstuvwxyz"),
        ("binding", "provider-owned-reference"),
        ("binding_id", "credential-123"),
        ("secret_id", "secret-123"),
        ("environment_variable", "OPENAI_API_KEY"),
        ("env_name", "OPENAI_API_KEY"),
        ("variable_name", "OPENAI_API_KEY"),
        ("keyring_entry", "continuityos/openai"),
        ("external_secret_id", "vault/path/item"),
    ],
)
def test_concrete_binding_fields_are_rejected_before_any_value_can_be_echoable(field, value):
    payload = {
        "reference_id": "service.primary",
        "provider": "environment",
        "purpose_id": "connector_auth",
        field: value,
    }
    with pytest.raises(vsr.SecretReferenceError, match="SECRET_BINDING_FIELD_FORBIDDEN"):
        vsr.validate_secret_reference(payload)


def test_build_api_has_no_locator_or_concrete_binding_parameter():
    parameters = inspect.signature(vsr.build_secret_reference).parameters
    assert "locator" not in parameters
    assert "binding" not in parameters
    assert "binding_id" not in parameters
    assert "secret_id" not in parameters


def test_provider_classes_never_imply_a_binding():
    for provider in vsr.SUPPORTED_PROVIDERS:
        receipt = vsr.build_secret_reference(
            reference_id="service.primary",
            provider=provider,
            purpose_id="connector_auth",
        )
        assert receipt["provider"] == provider
        assert receipt["binding_present"] is False
        assert receipt["binding_authorized"] is False
        assert "locator" not in receipt
        assert receipt["redaction"]["binding_locators"] == "NOT_ACCEPTED_IN_METADATA_ONLY_V1"


def test_validation_is_strict_and_canonical_json_is_stable_without_binding_locator():
    payload = {
        "schema": vsr.SCHEMA,
        "mode": vsr.MODE,
        "reference_id": "github.primary",
        "provider": "external",
        "secret_kind": "token",
        "purpose_id": "github_connector",
        "required": True,
    }

    first = vsr.canonical_secret_reference_json(payload)
    second = vsr.canonical_secret_reference_json(dict(reversed(list(payload.items()))))

    assert first == second
    decoded = json.loads(first)
    assert "locator" not in decoded
    assert decoded["binding_present"] is False
    assert decoded["binding_authorized"] is False
    assert decoded["secret_value_present"] is False
    assert decoded["live_secret_access_available"] is False

    with pytest.raises(vsr.SecretReferenceError, match="UNEXPECTED_FIELD"):
        vsr.validate_secret_reference({**payload, "notes": "arbitrary user text is not part of v1"})


def test_module_has_no_secret_backend_or_runtime_io_surface():
    source = Path(vsr.__file__).read_text(encoding="utf-8")

    forbidden_runtime_tokens = (
        "os.environ",
        "os.getenv",
        "load_dotenv",
        "keyring.get",
        "keyring.set",
        "CryptProtectData",
        "CryptUnprotectData",
        "subprocess.",
        "socket.",
        "requests.",
        "urllib.",
    )
    for token in forbidden_runtime_tokens:
        assert token not in source

    public = {name for name in dir(vsr) if not name.startswith("_")}
    assert "resolve_secret" not in public
    assert "read_secret" not in public
    assert "write_secret" not in public
    assert "store_secret" not in public
    assert "bind_secret" not in public
