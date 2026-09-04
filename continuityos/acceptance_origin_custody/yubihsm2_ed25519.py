"""Private YubiHSM2 Ed25519 adapter boundary for Acceptance Origin R1.

The checked-in production provider is intentionally unprovisioned. This module contains
no credentials, no environment/filesystem/network lookup, no HTTP connector, and no
vendor-library import. A later separately reviewed runtime-auth custody implementation
must bind the concrete local-USB session acquisition path.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_DIRECT_USB_CONNECTOR = "yhusb://"
_REQUIRED_CAPABILITIES = frozenset({"SIGN_EDDSA"})


@dataclass(frozen=True)
class _BoundYubiHsmProfile:
    signing_key_object_id: int
    runtime_auth_key_object_id: int
    signer_domain_bit: int
    connector_url: str

    def __post_init__(self) -> None:
        if type(self.signing_key_object_id) is not int or self.signing_key_object_id < 1:
            raise ValueError("production_hsm_binding_invalid")
        if type(self.runtime_auth_key_object_id) is not int or self.runtime_auth_key_object_id < 1:
            raise ValueError("production_hsm_binding_invalid")
        if type(self.signer_domain_bit) is not int or self.signer_domain_bit <= 0:
            raise ValueError("production_hsm_binding_invalid")
        if self.signer_domain_bit & (self.signer_domain_bit - 1):
            raise ValueError("production_hsm_domain_isolation_invalid")
        if self.connector_url != _DIRECT_USB_CONNECTOR:
            raise ValueError("production_hsm_connector_not_allowed")


class _RuntimeHsmSessionProvider:
    def _open_authenticated_session(self) -> Any:
        raise ValueError("production_hsm_auth_custody_unprovisioned")


class _UnprovisionedRuntimeHsmSessionProvider(_RuntimeHsmSessionProvider):
    pass


def _require_metadata_shape(value: Any, *, auth: bool) -> dict[str, Any]:
    expected = {
        "object_id", "object_type", "algorithm", "domains",
        "capabilities", "exportable",
    }
    if auth:
        expected.add("delegated_capabilities")
    if type(value) is not dict or set(value) != expected:
        raise ValueError("production_hsm_capability_profile_invalid")
    if type(value["domains"]) not in (set, frozenset):
        raise ValueError("production_hsm_capability_profile_invalid")
    if type(value["capabilities"]) not in (set, frozenset):
        raise ValueError("production_hsm_capability_profile_invalid")
    if auth and type(value["delegated_capabilities"]) not in (set, frozenset):
        raise ValueError("production_hsm_capability_profile_invalid")
    return value


class _YubiHsm2Ed25519Adapter:
    __slots__ = ("_profile", "_session_provider", "_public_key_readback")

    def __init__(
        self,
        *,
        profile: _BoundYubiHsmProfile,
        session_provider: _RuntimeHsmSessionProvider,
    ) -> None:
        self._profile = profile
        self._session_provider = session_provider
        self._public_key_readback: bytes | None = None

    def _open_session(self) -> Any:
        session = self._session_provider._open_authenticated_session()
        if session is None:
            raise ValueError("production_custody_backend_unavailable")
        return session

    def _validate_session_metadata(self, session: Any) -> None:
        try:
            visible = session._list_asymmetric_keys(self._profile.signer_domain_bit)
        except AttributeError as exc:
            raise ValueError("production_custody_backend_unavailable") from exc
        if type(visible) is not list or visible != [self._profile.signing_key_object_id]:
            raise ValueError("production_hsm_domain_isolation_invalid")
        try:
            key_info = session._get_asymmetric_key_info(
                self._profile.signing_key_object_id
            )
            auth_info = session._get_auth_key_info(
                self._profile.runtime_auth_key_object_id
            )
        except AttributeError as exc:
            raise ValueError("production_custody_backend_unavailable") from exc

        key_info = _require_metadata_shape(key_info, auth=False)
        auth_info = _require_metadata_shape(auth_info, auth=True)

        expected_domain = frozenset({self._profile.signer_domain_bit})
        if (
            key_info["object_id"] != self._profile.signing_key_object_id
            or key_info["object_type"] != "ASYMMETRIC_KEY"
            or key_info["algorithm"] != "EC_ED25519"
            or frozenset(key_info["domains"]) != expected_domain
            or frozenset(key_info["capabilities"]) != _REQUIRED_CAPABILITIES
            or key_info["exportable"] is not False
        ):
            raise ValueError("production_hsm_capability_profile_invalid")

        if (
            auth_info["object_id"] != self._profile.runtime_auth_key_object_id
            or auth_info["object_type"] != "AUTHENTICATION_KEY"
            or frozenset(auth_info["domains"]) != expected_domain
            or frozenset(auth_info["capabilities"]) != _REQUIRED_CAPABILITIES
            or frozenset(auth_info["delegated_capabilities"])
            or auth_info["exportable"] is not False
        ):
            raise ValueError("production_hsm_capability_profile_invalid")

    def _read_bound_public_key(self) -> bytes:
        session = self._open_session()
        self._validate_session_metadata(session)
        try:
            public_key = session._read_ed25519_public_key(
                self._profile.signing_key_object_id
            )
        except AttributeError as exc:
            raise ValueError("production_custody_backend_unavailable") from exc
        if type(public_key) is not bytes or len(public_key) != 32:
            raise ValueError("production_key_public_readback_invalid")
        self._public_key_readback = public_key
        return public_key

    def _sign_bound_acceptance_message(self, message: bytes) -> bytes:
        if type(message) is not bytes or not message:
            raise ValueError("production_hsm_sign_failed")
        if self._public_key_readback is None:
            raise ValueError("production_key_public_readback_invalid")
        session = self._open_session()
        try:
            signature = session._sign_ed25519(
                self._profile.signing_key_object_id, message
            )
        except AttributeError as exc:
            raise ValueError("production_custody_backend_unavailable") from exc
        if type(signature) is not bytes or len(signature) != 64:
            raise ValueError("production_hsm_sign_failed")
        return signature


def _build_yubihsm2_ed25519_adapter() -> _YubiHsm2Ed25519Adapter:
    # No concrete object IDs, domain, connector credential, or auth mechanism is
    # selected by the R7 builder scope. Later contract binding must replace this
    # fail-closed factory under its own exact source-write gate.
    raise ValueError("production_hsm_auth_custody_unprovisioned")
