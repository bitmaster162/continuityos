"""Metadata-only secret-reference declarations for the ContinuityOS vault roadmap.

The module accepts only bounded public metadata. It derives a stable opaque public
reference identifier and never accepts a caller-provided reference identifier, secret
value, or concrete binding locator. Purpose identifiers are selected from a closed
public allowlist and therefore cannot echo arbitrary caller-controlled bytes.

Provider values identify provider classes only. The module does not access or verify a
secret backend, resolve a binding, read environment variables or dotenv files, access
keyrings or DPAPI, or use filesystem, network, or subprocess capabilities.

The generated ``reference_id`` is a correlatable content identifier for the bounded
metadata declaration. It is not random, unpredictable, unique per concrete credential,
a binding locator, a secret, an event nonce, or execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

SCHEMA = "continuityos.vault_secret_reference/v1"
MODE = "METADATA_ONLY"
REFERENCE_ID_POLICY = "OPAQUE_STABLE_BOUNDED_METADATA_SHA256"
PURPOSE_ID_POLICY = "BOUNDED_ALLOWLIST"

SUPPORTED_PROVIDERS = ("unbound", "environment", "os-keyring", "external")
SUPPORTED_SECRET_KINDS = (
    "api_key",
    "token",
    "password",
    "private_key",
    "credential",
    "other",
)
SUPPORTED_PURPOSES = ("connector_auth", "cross_ai_demo")

_REFERENCE_ID_DOMAIN = b"continuityos.vault_secret_reference/reference-id/v1\0"

_ALLOWED_INPUT_FIELDS = frozenset(
    {
        "schema",
        "mode",
        "provider",
        "secret_kind",
        "purpose_id",
        "required",
    }
)

_FORBIDDEN_SECRET_FIELDS = frozenset(
    {
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
    }
)

_FORBIDDEN_BINDING_FIELDS = frozenset(
    {
        "locator",
        "binding",
        "binding_id",
        "secret_id",
        "environment_variable",
        "env_name",
        "variable_name",
        "keyring_entry",
        "external_secret_id",
    }
)


@dataclass(frozen=True)
class SecretReferenceError(ValueError):
    reason: str

    def __str__(self) -> str:
        return self.reason


def _bounded_string(value: Any, supported: tuple[str, ...], reason: str) -> str:
    if type(value) is not str or value not in supported:
        raise SecretReferenceError(reason)
    return value


def _opaque_reference_id(
    *,
    provider: str,
    secret_kind: str,
    purpose_id: str,
    required: bool,
) -> str:
    seed = json.dumps(
        {
            "schema": SCHEMA,
            "mode": MODE,
            "provider": provider,
            "secret_kind": secret_kind,
            "purpose_id": purpose_id,
            "required": required,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(_REFERENCE_ID_DOMAIN + seed.encode("ascii")).hexdigest()
    return f"vsr_{digest}"


def _purpose(value: Any) -> str:
    if type(value) is not str or value not in SUPPORTED_PURPOSES:
        raise SecretReferenceError("PURPOSE_UNSUPPORTED")
    return value


def _effects() -> dict[str, Any]:
    return {
        "caller_reference_identifier_accepted": False,
        "arbitrary_purpose_identifier_accepted": False,
        "secret_value_field_accepted": False,
        "dedicated_secret_value_read": False,
        "dedicated_secret_value_stored": False,
        "secret_binding_accepted": False,
        "secret_backend_accessed": False,
        "environment_read": False,
        "dotenv_read": False,
        "keyring_accessed": False,
        "dpapi_accessed": False,
        "filesystem_read": False,
        "filesystem_write": False,
        "network_effect": False,
        "subprocess_execution": False,
        "runtime_mutation": False,
        "pointer_mutation": False,
        "memory_mutation": False,
        "deployment": False,
    }


def _governance() -> dict[str, Any]:
    return {
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }


def build_secret_reference(
    *,
    provider: str = "unbound",
    secret_kind: str = "credential",
    purpose_id: str,
    required: bool = True,
) -> dict[str, Any]:
    """Build one metadata-only reference with a stable opaque public identifier.

    ``purpose_id`` is selected from ``SUPPORTED_PURPOSES``. No arbitrary purpose text,
    caller-provided reference identifier, secret value, or binding locator is accepted.
    Provider values describe a possible future provider lane and never imply a binding.
    The stable identifier names this bounded declaration, not a concrete credential.
    """
    provider_code = _bounded_string(provider, SUPPORTED_PROVIDERS, "PROVIDER_UNSUPPORTED")
    secret_kind_code = _bounded_string(
        secret_kind,
        SUPPORTED_SECRET_KINDS,
        "SECRET_KIND_UNSUPPORTED",
    )
    purpose_code = _purpose(purpose_id)
    if type(required) is not bool:
        raise SecretReferenceError("REQUIRED_INVALID")

    if provider_code == "unbound":
        readiness = "PROVIDER_UNBOUND"
    else:
        readiness = "PROVIDER_CLASS_DECLARED_BINDING_NOT_AUTHORIZED"

    return {
        "schema": SCHEMA,
        "mode": MODE,
        "reference_id": _opaque_reference_id(
            provider=provider_code,
            secret_kind=secret_kind_code,
            purpose_id=purpose_code,
            required=required,
        ),
        "reference_id_policy": REFERENCE_ID_POLICY,
        "provider": provider_code,
        "secret_kind": secret_kind_code,
        "purpose_id": purpose_code,
        "purpose_id_policy": PURPOSE_ID_POLICY,
        "required": required,
        "readiness": readiness,
        "binding_present": False,
        "binding_authorized": False,
        "dedicated_secret_value_present": False,
        "live_secret_access_available": False,
        "redaction": {
            "caller_reference_identifiers": "NOT_ACCEPTED",
            "purpose_identifiers": "BOUNDED_ALLOWLIST_ONLY",
            "secret_values": "NO_SECRET_VALUE_FIELDS_ACCEPTED",
            "binding_locators": "NOT_ACCEPTED_IN_METADATA_ONLY_V1",
        },
        "effects": _effects(),
        **_governance(),
    }


def validate_secret_reference(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate a bounded declaration and return a new canonical public receipt."""
    if type(payload) is not dict:
        raise SecretReferenceError("PAYLOAD_INVALID")

    for key in payload:
        if type(key) is not str:
            raise SecretReferenceError("UNEXPECTED_FIELD")
    keys = set(payload)
    forbidden_secret = keys & _FORBIDDEN_SECRET_FIELDS
    if forbidden_secret:
        raise SecretReferenceError("SECRET_VALUE_FIELD_FORBIDDEN")

    forbidden_binding = keys & _FORBIDDEN_BINDING_FIELDS
    if forbidden_binding:
        raise SecretReferenceError("SECRET_BINDING_FIELD_FORBIDDEN")

    if "reference_id" in keys:
        raise SecretReferenceError("CALLER_REFERENCE_ID_FORBIDDEN")

    unexpected = keys - _ALLOWED_INPUT_FIELDS
    if unexpected:
        raise SecretReferenceError("UNEXPECTED_FIELD")

    schema = payload.get("schema", SCHEMA)
    mode = payload.get("mode", MODE)
    if type(schema) is not str or schema != SCHEMA:
        raise SecretReferenceError("SCHEMA_UNSUPPORTED")
    if type(mode) is not str or mode != MODE:
        raise SecretReferenceError("MODE_UNSUPPORTED")

    return build_secret_reference(
        provider=payload.get("provider", "unbound"),
        secret_kind=payload.get("secret_kind", "credential"),
        purpose_id=payload.get("purpose_id"),
        required=payload.get("required", True),
    )


def canonical_secret_reference_json(payload: dict[str, Any]) -> str:
    """Build one stable receipt and serialize it with deterministic JSON ordering."""
    receipt = validate_secret_reference(payload)
    return json.dumps(
        receipt,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
