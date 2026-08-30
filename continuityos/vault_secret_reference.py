"""Secret-reference metadata contract for the ContinuityOS vault roadmap.

This module is deliberately metadata-only. It accepts bounded public metadata fields,
but it accepts no dedicated secret-value fields or concrete secret-binding fields and
does not read, store, resolve, or verify secrets. It also does not access environment
variables, .env files, OS keyrings, DPAPI, network services, runtime state, or the
filesystem.

``reference_id`` and ``purpose_id`` are public caller-provided identifiers. They are
returned in the public receipt and MUST contain only non-sensitive metadata; callers
are responsible for never placing secret material in those identifier fields. Provider
values in this v1 contract are provider *classes* only; no environment variable name,
keyring entry, external secret ID, token-like locator, or other concrete binding
identifier is accepted or returned.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping

SCHEMA = "continuityos.vault_secret_reference/v1"
MODE = "METADATA_ONLY"
PUBLIC_IDENTIFIER_POLICY = "PUBLIC_NON_SENSITIVE_CALLER_RESPONSIBILITY"

SUPPORTED_PROVIDERS = ("unbound", "environment", "os-keyring", "external")
SUPPORTED_SECRET_KINDS = (
    "api_key",
    "token",
    "password",
    "private_key",
    "credential",
    "other",
)

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

_ALLOWED_INPUT_FIELDS = frozenset(
    {
        "schema",
        "mode",
        "reference_id",
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


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SecretReferenceError(f"{field.upper()}_INVALID")
    return value


def _effects() -> dict[str, Any]:
    return {
        "secret_value_field_accepted": False,
        "secret_value_read": False,
        "secret_value_stored": False,
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
    reference_id: str,
    provider: str = "unbound",
    secret_kind: str = "credential",
    purpose_id: str,
    required: bool = True,
) -> dict[str, Any]:
    """Build one bounded metadata-only secret reference.

    ``reference_id`` and ``purpose_id`` are public caller-provided identifiers that are
    echoed in the receipt and must be non-sensitive. ``provider`` is only a provider
    class describing a possible future binding lane. This function accepts no dedicated
    secret-value field or concrete binding locator and performs no provider access.
    """
    ref_id = _identifier(reference_id, "reference_id")
    purpose = _identifier(purpose_id, "purpose_id")

    if provider not in SUPPORTED_PROVIDERS:
        raise SecretReferenceError("PROVIDER_UNSUPPORTED")
    if secret_kind not in SUPPORTED_SECRET_KINDS:
        raise SecretReferenceError("SECRET_KIND_UNSUPPORTED")
    if type(required) is not bool:
        raise SecretReferenceError("REQUIRED_INVALID")

    if provider == "unbound":
        readiness = "PROVIDER_UNBOUND"
    else:
        readiness = "PROVIDER_CLASS_DECLARED_BINDING_NOT_AUTHORIZED"

    return {
        "schema": SCHEMA,
        "mode": MODE,
        "reference_id": ref_id,
        "provider": provider,
        "secret_kind": secret_kind,
        "purpose_id": purpose,
        "required": required,
        "identifier_policy": {
            "reference_id": PUBLIC_IDENTIFIER_POLICY,
            "purpose_id": PUBLIC_IDENTIFIER_POLICY,
        },
        "readiness": readiness,
        "binding_present": False,
        "binding_authorized": False,
        "dedicated_secret_value_present": False,
        "live_secret_access_available": False,
        "redaction": {
            "secret_values": "NO_SECRET_VALUE_FIELDS_ACCEPTED",
            "binding_locators": "NOT_ACCEPTED_IN_METADATA_ONLY_V1",
        },
        "effects": _effects(),
        **_governance(),
    }


def validate_secret_reference(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an input declaration and return the canonical public receipt.

    The accepted input shape intentionally excludes all dedicated secret-bearing value
    fields, concrete secret-binding fields, and receipt/status fields. The public
    ``reference_id`` and ``purpose_id`` fields are caller-responsible non-sensitive
    metadata and are returned verbatim after bounded identifier-shape validation.
    Binding identifiers are a separate future lane and cannot be smuggled into this
    metadata-only v1 object.
    """
    if not isinstance(payload, Mapping):
        raise SecretReferenceError("PAYLOAD_INVALID")

    keys = set(payload)
    forbidden_secret = keys & _FORBIDDEN_SECRET_FIELDS
    if forbidden_secret:
        raise SecretReferenceError("SECRET_VALUE_FIELD_FORBIDDEN")

    forbidden_binding = keys & _FORBIDDEN_BINDING_FIELDS
    if forbidden_binding:
        raise SecretReferenceError("SECRET_BINDING_FIELD_FORBIDDEN")

    unexpected = keys - _ALLOWED_INPUT_FIELDS
    if unexpected:
        raise SecretReferenceError("UNEXPECTED_FIELD")

    if payload.get("schema", SCHEMA) != SCHEMA:
        raise SecretReferenceError("SCHEMA_UNSUPPORTED")
    if payload.get("mode", MODE) != MODE:
        raise SecretReferenceError("MODE_UNSUPPORTED")

    return build_secret_reference(
        reference_id=payload.get("reference_id"),
        provider=payload.get("provider", "unbound"),
        secret_kind=payload.get("secret_kind", "credential"),
        purpose_id=payload.get("purpose_id"),
        required=payload.get("required", True),
    )


def canonical_secret_reference_json(payload: Mapping[str, Any]) -> str:
    """Return deterministic JSON for the canonical metadata-only receipt."""
    receipt = validate_secret_reference(payload)
    return json.dumps(
        receipt,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
