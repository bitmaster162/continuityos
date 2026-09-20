"""Read-only R15D product binding for an already provisioned Windows TPM anchor.

This module never provisions, defines, primes, clears, undefines, or extends TPM
state. It reconstructs the reviewed R15B profile from explicit external
configuration, verifies the controller pin and DPAPI custody envelope, performs
one read-only hardware snapshot, and returns the R15 monotonic anchor adapter.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from .monotonic_anchor import MonotonicExecutionAnchor
from .tpm2_provider_binding import BoundTpm2NvExtendProvider
from .windows_tpm_dpapi import DpapiIndexAuthStore
from .windows_tpm_provisioning import build_reviewed_plan
from .windows_tpm_runtime import WindowsTbsNvExtendBackend

_HEX = frozenset("0123456789abcdef")
_CUSTODY_SCHEMA = "continuityos.r15b.windows-dpapi-index-auth/v1"


class WindowsTpmProductRuntimeError(RuntimeError):
    """Explicit R15 product runtime configuration or binding is invalid."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or set(value) - _HEX
    ):
        raise WindowsTpmProductRuntimeError(f"{label} is not lowercase SHA-256")
    return value


def _read_absolute_file(path: str, label: str) -> tuple[Path, bytes]:
    if not isinstance(path, str) or not path.strip():
        raise WindowsTpmProductRuntimeError(f"{label} path is required")
    target = Path(path).expanduser()
    if not target.is_absolute():
        raise WindowsTpmProductRuntimeError(f"{label} path must be absolute")
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise WindowsTpmProductRuntimeError(f"{label} is unreadable") from exc
    if not data:
        raise WindowsTpmProductRuntimeError(f"{label} is empty")
    return target, data


def _json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WindowsTpmProductRuntimeError(f"{label} is not canonical ASCII JSON") from exc
    if type(value) is not dict:
        raise WindowsTpmProductRuntimeError(f"{label} must be a JSON object")
    return value


def _custody_metadata(path: str) -> tuple[Path, dict[str, Any]]:
    target, raw = _read_absolute_file(path, "R15 DPAPI custody")
    payload = _json_object(raw, "R15 DPAPI custody")
    expected = {
        "schema", "provider", "nv_index", "ek_public_sha256", "ciphertext_b64"
    }
    if set(payload) != expected:
        raise WindowsTpmProductRuntimeError("R15 DPAPI custody envelope schema is invalid")
    if (
        payload["schema"] != _CUSTODY_SCHEMA
        or payload["provider"] != "WINDOWS_DPAPI_CURRENT_USER"
        or type(payload["nv_index"]) is not int
    ):
        raise WindowsTpmProductRuntimeError("R15 DPAPI custody envelope identity is invalid")
    _require_sha256(payload["ek_public_sha256"], "R15 custody EK identity")
    try:
        ciphertext = base64.b64decode(payload["ciphertext_b64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise WindowsTpmProductRuntimeError("R15 DPAPI custody ciphertext is invalid") from exc
    if not ciphertext:
        raise WindowsTpmProductRuntimeError("R15 DPAPI custody ciphertext is empty")
    return target, payload


def build_windows_r15_monotonic_anchor(
    *,
    controller_profile_path: str,
    controller_profile_sha256: str,
    custody_path: str,
    backend_factory: Callable[[DpapiIndexAuthStore], Any] | None = None,
) -> MonotonicExecutionAnchor:
    """Bind product runtime to existing R15 hardware without any TPM mutation."""
    expected_controller_sha = _require_sha256(
        controller_profile_sha256, "R15 controller profile pin"
    )
    controller_path, controller_raw = _read_absolute_file(
        controller_profile_path, "R15 controller profile"
    )
    observed_controller_sha = _sha256_bytes(controller_raw)
    if observed_controller_sha != expected_controller_sha:
        raise WindowsTpmProductRuntimeError(
            "R15 controller profile SHA-256 differs from explicit pin"
        )
    controller = _json_object(controller_raw, "R15 controller profile")

    custody_target, custody = _custody_metadata(custody_path)
    nv_index = custody["nv_index"]
    if controller.get("nv_index") != nv_index:
        raise WindowsTpmProductRuntimeError(
            "R15 controller profile NV index differs from custody"
        )

    plan = build_reviewed_plan(
        ek_public_sha256=custody["ek_public_sha256"],
        nv_index=nv_index,
    )
    profile = plan.active_profile
    if controller != profile.binding_document():
        raise WindowsTpmProductRuntimeError(
            "R15 controller profile differs from reviewed Windows TPM binding"
        )

    secret_store = DpapiIndexAuthStore(
        custody_target,
        nv_index=nv_index,
        ek_public_sha256=custody["ek_public_sha256"],
    )
    factory = backend_factory or WindowsTbsNvExtendBackend
    backend = factory(secret_store)
    provider = BoundTpm2NvExtendProvider(backend, profile=profile)

    # Mandatory startup proof is read-only: NV_Read + public identity read.
    provider.read_snapshot()
    return MonotonicExecutionAnchor(
        provider, profile=profile.anchor_profile()
    )
