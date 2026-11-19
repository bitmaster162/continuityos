"""Narrow Windows TBS runtime backend for one provisioned R15B NV_EXTEND index.

The runtime surface contains only authorized NV_Read and NV_Extend plus public
NV_ReadPublic verification.  It has no define, undefine, clear, reset, owner
authorization retrieval, provisioning, or generic TPM command API.
"""
from __future__ import annotations

import ctypes
import struct
from typing import Any, Callable

from .tpm2_provider_binding import (
    BoundTpm2NvExtendProfile,
    Tpm2ProviderBindingError,
)
from .windows_tpm_dpapi import DpapiIndexAuthStore, zeroize
from .windows_tpm_readonly import (
    TBS_COMMAND_LOCALITY_ZERO,
    TBS_COMMAND_PRIORITY_LOW,
    TBS_CONTEXT_FLAGS,
    TBS_SUCCESS,
    TPM_VERSION_20,
    _MAX_TPM_RESPONSE,
    _TbsContextParams2,
    _load_tbs,
    read_nv_public,
)

TPM_ST_SESSIONS = 0x8002
TPM_RS_PW = 0x40000009
TPM_CC_NV_EXTEND = 0x00000136
TPM_CC_NV_READ = 0x0000014E

_ALLOWED_RUNTIME_COMMANDS = frozenset({TPM_CC_NV_READ, TPM_CC_NV_EXTEND})


class WindowsTpmRuntimeError(Tpm2ProviderBindingError):
    """The narrow Windows runtime TPM boundary failed closed."""


def _is_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _pw_authorization_area(auth_value: bytearray) -> bytes:
    if type(auth_value) is not bytearray or len(auth_value) != 32:
        raise WindowsTpmRuntimeError("runtime index authValue must be 32 bytes")
    return b"".join((
        struct.pack(">I", TPM_RS_PW),
        struct.pack(">H", 0),
        b"\x00",
        struct.pack(">H", len(auth_value)),
        bytes(auth_value),
    ))


def _session_command(
    *,
    command_code: int,
    handles: tuple[int, ...],
    auth_value: bytearray,
    parameters: bytes,
) -> bytes:
    if command_code not in _ALLOWED_RUNTIME_COMMANDS:
        raise WindowsTpmRuntimeError("TPM command is outside runtime allowlist")
    if not handles or any(type(item) is not int for item in handles):
        raise WindowsTpmRuntimeError("runtime TPM handles are invalid")
    if type(parameters) is not bytes:
        raise WindowsTpmRuntimeError("runtime TPM parameters must be bytes")
    handle_bytes = b"".join(struct.pack(">I", item) for item in handles)
    auth_area = _pw_authorization_area(auth_value)
    body = (
        handle_bytes
        + struct.pack(">I", len(auth_area))
        + auth_area
        + parameters
    )
    return struct.pack(
        ">HII", TPM_ST_SESSIONS, 10 + len(body), command_code
    ) + body


def _require_pw_response(data: bytes) -> bytes:
    if type(data) is not bytes or len(data) < 14:
        raise WindowsTpmRuntimeError("TPM runtime response is truncated")
    tag, declared_size, response_code = struct.unpack(">HII", data[:10])
    if declared_size != len(data):
        raise WindowsTpmRuntimeError("TPM runtime response size mismatch")
    if response_code != 0:
        raise WindowsTpmRuntimeError(
            f"TPM runtime command failed with response code 0x{response_code:08x}"
        )
    if tag != TPM_ST_SESSIONS:
        raise WindowsTpmRuntimeError("TPM runtime response session tag is invalid")
    parameter_size = int.from_bytes(data[10:14], "big")
    parameter_end = 14 + parameter_size
    if parameter_end > len(data):
        raise WindowsTpmRuntimeError("TPM runtime parameter area is truncated")
    parameters = data[14:parameter_end]
    auth = data[parameter_end:]
    if len(auth) != 5:
        raise WindowsTpmRuntimeError("TPM password response auth area is invalid")
    nonce_size = int.from_bytes(auth[0:2], "big")
    attrs = auth[2]
    hmac_size = int.from_bytes(auth[3:5], "big")
    # TPM 2.0 requires continueSession (bit 0) SET in the response for
    # password authorization, even though the bit has no password-session
    # lifetime semantics. No other session attribute is valid here.
    if nonce_size != 0 or attrs != 0x01 or hmac_size != 0:
        raise WindowsTpmRuntimeError(
            "TPM password response auth area is invalid"
        )
    return parameters


class _WindowsTbsNvTransport:
    """Private transport with exactly two effectful TPM command codes."""

    def _submit(self, command: bytes) -> bytes:
        if type(command) is not bytes or len(command) < 10:
            raise WindowsTpmRuntimeError("runtime TPM command is invalid")
        _, declared_size, command_code = struct.unpack(">HII", command[:10])
        if declared_size != len(command) or command_code not in _ALLOWED_RUNTIME_COMMANDS:
            raise WindowsTpmRuntimeError("runtime TPM command is outside allowlist")
        dll = _load_tbs()
        params = _TbsContextParams2(TPM_VERSION_20, TBS_CONTEXT_FLAGS)
        context = ctypes.c_void_p()
        result = dll.Tbsi_Context_Create(
            ctypes.byref(params), ctypes.byref(context)
        )
        if result != TBS_SUCCESS or not context.value:
            raise WindowsTpmRuntimeError(
                f"TBS runtime context creation failed with 0x{result:08x}"
            )
        try:
            in_buffer = (ctypes.c_ubyte * len(command)).from_buffer_copy(command)
            out_buffer = (ctypes.c_ubyte * _MAX_TPM_RESPONSE)()
            out_size = ctypes.c_uint32(len(out_buffer))
            result = dll.Tbsip_Submit_Command(
                context,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_LOW,
                in_buffer,
                len(command),
                out_buffer,
                ctypes.byref(out_size),
            )
            if result != TBS_SUCCESS:
                raise WindowsTpmRuntimeError(
                    f"TBS runtime submit failed with 0x{result:08x}"
                )
            if out_size.value > _MAX_TPM_RESPONSE:
                raise WindowsTpmRuntimeError("runtime TPM response exceeded buffer")
            return _require_pw_response(bytes(out_buffer[: out_size.value]))
        finally:
            close_result = dll.Tbsip_Context_Close(context)
            if close_result != TBS_SUCCESS:
                raise WindowsTpmRuntimeError(
                    f"TBS runtime close failed with 0x{close_result:08x}"
                )

    def nv_read(self, *, nv_index: int, auth_value: bytearray) -> bytes:
        command = _session_command(
            command_code=TPM_CC_NV_READ,
            handles=(nv_index, nv_index),
            auth_value=auth_value,
            parameters=struct.pack(">HH", 32, 0),
        )
        parameters = self._submit(command)
        if len(parameters) != 34:
            raise WindowsTpmRuntimeError("NV_Read response size is invalid")
        size = int.from_bytes(parameters[:2], "big")
        digest = parameters[2:]
        if size != 32 or len(digest) != 32:
            raise WindowsTpmRuntimeError("NV_Read digest size is invalid")
        return digest

    def nv_extend(
        self,
        *,
        nv_index: int,
        auth_value: bytearray,
        commitment: bytes,
    ) -> None:
        if type(commitment) is not bytes or len(commitment) != 32:
            raise WindowsTpmRuntimeError("NV_Extend commitment must be 32 bytes")
        command = _session_command(
            command_code=TPM_CC_NV_EXTEND,
            handles=(nv_index, nv_index),
            auth_value=auth_value,
            parameters=struct.pack(">H", len(commitment)) + commitment,
        )
        parameters = self._submit(command)
        if parameters != b"":
            raise WindowsTpmRuntimeError("NV_Extend returned unexpected parameters")


class WindowsTbsNvExtendBackend:
    """Bound runtime backend using DPAPI index auth and a stable WRITTEN profile."""

    def __init__(
        self,
        secret_store: DpapiIndexAuthStore,
        *,
        transport: Any | None = None,
        public_reader: Callable[[int], dict[str, Any]] | None = None,
    ) -> None:
        if secret_store is None:
            raise WindowsTpmRuntimeError("runtime DPAPI secret store is required")
        self._secret_store = secret_store
        self._transport = transport or _WindowsTbsNvTransport()
        self._public_reader = public_reader or read_nv_public

    @staticmethod
    def _commitment_bytes(value: str) -> bytes:
        if not _is_sha256(value) or value == "0" * 64:
            raise WindowsTpmRuntimeError("runtime commitment digest is invalid")
        return bytes.fromhex(value)

    def _public_snapshot(
        self, *, profile: BoundTpm2NvExtendProfile
    ) -> dict[str, Any]:
        public = self._public_reader(profile.constraints.nv_index)
        required = {
            "nv_index", "name_alg", "tpma_nv_mask", "nv_type_bits", "nv_type",
            "data_size", "orderly", "auth_policy_hex", "auth_policy_sha256",
            "tpms_nv_public_marshaled", "raw_tpm_name", "nv_public_sha256",
            "nv_name_sha256", "name_verified",
        }
        if type(public) is not dict or set(public) != required:
            raise WindowsTpmRuntimeError("runtime NV public snapshot schema is invalid")
        if public["name_verified"] is not True:
            raise WindowsTpmRuntimeError("runtime NV Name is not verified")
        return public

    def read_snapshot(
        self, *, profile: BoundTpm2NvExtendProfile
    ) -> dict[str, Any]:
        public = self._public_snapshot(profile=profile)
        secret = self._secret_store.load()
        try:
            digest = self._transport.nv_read(
                nv_index=profile.constraints.nv_index,
                auth_value=secret,
            )
        finally:
            zeroize(secret)
        if type(digest) is not bytes or len(digest) != 32:
            raise WindowsTpmRuntimeError("runtime NV digest is invalid")
        return {
            "nv_index": public["nv_index"],
            "tpma_nv_mask": public["tpma_nv_mask"],
            "auth_policy_sha256": public["auth_policy_sha256"],
            "backend_kind": profile.constraints.backend_kind,
            "transport_identity": profile.constraints.transport_identity,
            "nv_type": public["nv_type"],
            "name_alg": "SHA256" if public["name_alg"] == 0x000B else "OTHER",
            "data_size": public["data_size"],
            "orderly": public["orderly"],
            "tpms_nv_public_marshaled": public["tpms_nv_public_marshaled"],
            "raw_tpm_name": public["raw_tpm_name"],
            "observed_nv_extend_digest": digest.hex(),
        }

    def extend_once(
        self,
        *,
        profile: BoundTpm2NvExtendProfile,
        expected_previous_digest: str,
        commitment_sha256: str,
    ) -> dict[str, Any]:
        before = self.read_snapshot(profile=profile)
        if before["observed_nv_extend_digest"] != expected_previous_digest:
            raise WindowsTpmRuntimeError("runtime TPM frontier moved before extend")
        commitment = self._commitment_bytes(commitment_sha256)
        secret = self._secret_store.load()
        try:
            self._transport.nv_extend(
                nv_index=profile.constraints.nv_index,
                auth_value=secret,
                commitment=commitment,
            )
        finally:
            zeroize(secret)
        return self.read_snapshot(profile=profile)
