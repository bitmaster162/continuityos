"""Secret-reference metadata contract for the ContinuityOS vault roadmap.

This module is deliberately metadata-only. It does not read, accept, store, resolve,
or verify secret values and it does not access environment variables, .env files,
OS keyrings, DPAPI, network services, runtime state, or the filesystem.

A secret reference is only a bounded declaration that a future vault implementation
may bind under a separate authorization gate.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping

SCHEMA = "continuityos.vault_secret_reference/v1"
MODE = "METADATA_ONLY"

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
_LOCATOR = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,127}$")

_ALLOWED_INPUT_FIELDS = frozenset(
    {
        "schema",
        "mode",
        "reference_id",
        "provider",
        "locator",
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


@dataclass(frozen=True)
class SecretReferenceError(ValueError):
    reason: str

    def __str__(self) -> str:
        return self.reason


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SecretReferenceError(f"{field.upper()}_INVALID")
    return value


def _locator(value: Any) -> str:
    if not isinstance(value, str) or not _LOCATOR.fullmatch(value):
        raise SecretReferenceError("LOCATOR_INVALID")
    return value


def _effects() -> dict[str, Any]:
    return {
        "secret_value_accepted": False,
        "secret_value_read": False,
        "secret_value_stored": False,
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
    locator: str | None = None,
    secret_kind: str = "credential",
    purpose_id: str,
    required: bool = True,
) -> dict[str, Any]:
    """Build one bounded metadata-only secret reference.

    ``locator`` is an identifier such as an environment variable name or future
    provider-owned reference key. It is never interpreted or dereferenced here.
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
        if locator is not None:
            raise SecretReferenceError("UNBOUND_PROVIDER_MUST_NOT_HAVE_LOCATOR")
        normalized_locator = None
        readiness = "PROVIDER_UNBOUND"
    else:
        if locator is None:
            raise SecretReferenceError("BOUND_PROVIDER_REQUIRES_LOCATOR")
        normalized_locator = _locator(locator)
        readiness = "REFERENCE_DECLARED_NOT_VERIFIED"

    return {
        "schema": SCHEMA,
        "mode": MODE,
        "reference_id": ref_id,
        "provider": provider,
        "locator": normalized_locator,
        "secret_kind": secret_kind,
        "purpose_id": purpose,
        "required": required,
        "readiness": readiness,
        "secret_value_present": False,
        "live_secret_access_available": False,
        "redaction": {
            "secret_values": "NEVER_ACCEPTED_OR_INCLUDED",
            "locator_class": "IDENTIFIER_ONLY",
        },
        "effects": _effects(),
        **_governance(),
    }


def validate_secret_reference(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an input declaration and return the canonical public receipt.

    The accepted input shape intentionally excludes all secret-bearing value fields
    and all receipt/status fields. Callers cannot smuggle a secret value into the
    canonical metadata object as an "extra" property.
    """
    if not isinstance(payload, Mapping):
        raise SecretReferenceError("PAYLOAD_INVALID")

    keys = set(payload)
    forbidden = keys & _FORBIDDEN_SECRET_FIELDS
    if forbidden:
        raise SecretReferenceError("SECRET_VALUE_FIELD_FORBIDDEN")

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
        locator=payload.get("locator"),
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
