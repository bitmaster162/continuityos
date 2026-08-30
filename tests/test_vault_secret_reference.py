from __future__ import annotations

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
    assert receipt["locator"] is None
    assert receipt["readiness"] == "PROVIDER_UNBOUND"
    assert receipt["secret_value_present"] is False
    assert receipt["live_secret_access_available"] is False
    assert receipt["execution_authority"] == "NONE"
    assert receipt["can_execute"] is False
    assert receipt["can_trade"] is False
    assert receipt["capital_permission"] == "DENY"
    assert all(value is False for value in receipt["effects"].values())


def test_declared_environment_reference_never_reads_or_verifies_environment(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "super-secret-value-that-must-never-be-read")

    receipt = vsr.build_secret_reference(
        reference_id="openai.primary",
        provider="environment",
        locator="OPENAI_API_KEY",
        purpose_id="cross_ai_demo",
        secret_kind="api_key",
    )

    encoded = json.dumps(receipt, sort_keys=True)
    assert receipt["readiness"] == "REFERENCE_DECLARED_NOT_VERIFIED"
    assert receipt["locator"] == "OPENAI_API_KEY"
    assert receipt["effects"]["environment_read"] is False
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
    "locator",
    [
        "API_KEY=secret",
        "api key",
        "token\nvalue",
        "Bearer abc",
        "abc$def",
        "",
    ],
)
def test_locator_is_identifier_only_and_rejects_value_like_shapes(locator):
    with pytest.raises(vsr.SecretReferenceError, match="LOCATOR_INVALID"):
        vsr.build_secret_reference(
            reference_id="service.primary",
            provider="environment",
            locator=locator,
            purpose_id="connector_auth",
        )


def test_provider_binding_rules_fail_closed():
    with pytest.raises(vsr.SecretReferenceError, match="UNBOUND_PROVIDER_MUST_NOT_HAVE_LOCATOR"):
        vsr.build_secret_reference(
            reference_id="service.primary",
            provider="unbound",
            locator="SHOULD_NOT_BE_HERE",
            purpose_id="connector_auth",
        )

    for provider in ("environment", "os-keyring", "external"):
        with pytest.raises(vsr.SecretReferenceError, match="BOUND_PROVIDER_REQUIRES_LOCATOR"):
            vsr.build_secret_reference(
                reference_id="service.primary",
                provider=provider,
                purpose_id="connector_auth",
            )


def test_validation_is_strict_and_canonical_json_is_stable():
    payload = {
        "schema": vsr.SCHEMA,
        "mode": vsr.MODE,
        "reference_id": "github.primary",
        "provider": "external",
        "locator": "github/pat/primary",
        "secret_kind": "token",
        "purpose_id": "github_connector",
        "required": True,
    }

    first = vsr.canonical_secret_reference_json(payload)
    second = vsr.canonical_secret_reference_json(dict(reversed(list(payload.items()))))

    assert first == second
    decoded = json.loads(first)
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
