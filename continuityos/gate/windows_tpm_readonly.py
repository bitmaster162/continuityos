"""Windows TPM 2.0 read-only discovery boundary for R15B.

This module talks to Windows TPM Base Services (TBS) only for unauthenticated
public discovery. The only TPM commands implemented are TPM2_GetCapability and
TPM2_NV_ReadPublic. It has no NV_Read, session/auth, write, extend, provision,
reset, clear, undefine, hierarchy, or arbitrary-command surface.
"""
from __future__ import annotations

import ctypes
import hashlib
import struct
import sys
from typing import Any

from .tpm2_provider_binding import _parse_tpms_nv_public

TPM_ST_NO_SESSIONS = 0x8001
TPM_CC_NV_READ_PUBLIC = 0x00000169
TPM_CC_GET_CAPABILITY = 0x0000017A
TPM_CAP_HANDLES = 0x00000001
TPM_HR_NV_INDEX = 0x01000000
TPM_HR_NV_INDEX_LAST = 0x01FFFFFF
TPM_ALG_SHA256 = 0x000B
TPMA_NV_NT_MASK = 0x000000F0
TPMA_NV_ORDERLY = 0x04000000
TPM_NT_NAMES = {
    0x00: "TPM_NT_ORDINARY",
    0x10: "TPM_NT_COUNTER",
    0x20: "TPM_NT_BITS",
    0x40: "TPM_NT_EXTEND",
    0x80: "TPM_NT_PIN_FAIL",
    0x90: "TPM_NT_PIN_PASS",
}

TBS_SUCCESS = 0
TBS_COMMAND_LOCALITY_ZERO = 0
TBS_COMMAND_PRIORITY_LOW = 100
TPM_VERSION_20 = 2
TBS_CONTEXT_REQUEST_RAW = 0x1
TBS_CONTEXT_INCLUDE_TPM20 = 0x4
TBS_CONTEXT_FLAGS = TBS_CONTEXT_REQUEST_RAW | TBS_CONTEXT_INCLUDE_TPM20

_MAX_TPM_RESPONSE = 65536
_MAX_DISCOVERY_PAGES = 64
_MAX_HANDLES_PER_PAGE = 64


class WindowsTpmReadOnlyError(RuntimeError):
    """Windows TBS or TPM public discovery failed closed."""


class _TbsContextParams2(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("flags", ctypes.c_uint32)]
def _require_windows() -> None:
    if sys.platform != "win32":
        raise WindowsTpmReadOnlyError("Windows TBS backend requires win32")


def _load_tbs():
    _require_windows()
    try:
        dll = ctypes.WinDLL("tbs.dll")
    except Exception as exc:
        raise WindowsTpmReadOnlyError("Windows tbs.dll is unavailable") from exc
    dll.Tbsi_Context_Create.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
    ]
    dll.Tbsi_Context_Create.restype = ctypes.c_uint32
    dll.Tbsip_Context_Close.argtypes = [ctypes.c_void_p]
    dll.Tbsip_Context_Close.restype = ctypes.c_uint32
    dll.Tbsip_Submit_Command.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    dll.Tbsip_Submit_Command.restype = ctypes.c_uint32
    return dll


def _tpm_header(command_code: int, parameter_size: int) -> bytes:
    total = 10 + parameter_size
    return struct.pack(">HII", TPM_ST_NO_SESSIONS, total, command_code)
def _require_response(data: bytes) -> bytes:
    if type(data) is not bytes or len(data) < 10:
        raise WindowsTpmReadOnlyError("TPM response is truncated")
    tag, declared_size, response_code = struct.unpack(">HII", data[:10])
    if tag != TPM_ST_NO_SESSIONS:
        raise WindowsTpmReadOnlyError("unexpected TPM response session tag")
    if declared_size != len(data):
        raise WindowsTpmReadOnlyError("TPM response size mismatch")
    if response_code != 0:
        raise WindowsTpmReadOnlyError(
            f"TPM command failed with response code 0x{response_code:08x}"
        )
    return data[10:]


def _submit_readonly(command_code: int, parameters: bytes) -> bytes:
    if command_code not in {TPM_CC_GET_CAPABILITY, TPM_CC_NV_READ_PUBLIC}:
        raise WindowsTpmReadOnlyError("TPM command is outside read-only allowlist")
    if type(parameters) is not bytes:
        raise WindowsTpmReadOnlyError("TPM command parameters must be bytes")
    expected_length = {TPM_CC_GET_CAPABILITY: 12, TPM_CC_NV_READ_PUBLIC: 4}[command_code]
    if len(parameters) != expected_length:
        raise WindowsTpmReadOnlyError("TPM read-only command parameter length is invalid")
    dll = _load_tbs()
    params = _TbsContextParams2(TPM_VERSION_20, TBS_CONTEXT_FLAGS)
    context = ctypes.c_void_p()
    result = dll.Tbsi_Context_Create(ctypes.byref(params), ctypes.byref(context))
    if result != TBS_SUCCESS or not context.value:
        raise WindowsTpmReadOnlyError(
            f"TBS context creation failed with 0x{result:08x}"
        )
    try:
        command = _tpm_header(command_code, len(parameters)) + parameters
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
            raise WindowsTpmReadOnlyError(
                f"TBS submit failed with 0x{result:08x}"
            )
        if out_size.value > _MAX_TPM_RESPONSE:
            raise WindowsTpmReadOnlyError("TPM response exceeded bounded buffer")
        return _require_response(bytes(out_buffer[: out_size.value]))
    finally:
        close_result = dll.Tbsip_Context_Close(context)
        if close_result != TBS_SUCCESS:
            raise WindowsTpmReadOnlyError(
                f"TBS context close failed with 0x{close_result:08x}"
            )
def _parse_get_capability_handles(payload: bytes) -> tuple[bool, list[int]]:
    if type(payload) is not bytes or len(payload) < 9:
        raise WindowsTpmReadOnlyError("TPM GetCapability response is truncated")
    more_data = payload[0]
    capability, count = struct.unpack(">II", payload[1:9])
    if more_data not in (0, 1) or capability != TPM_CAP_HANDLES:
        raise WindowsTpmReadOnlyError("TPM GetCapability response is invalid")
    if count > _MAX_HANDLES_PER_PAGE or len(payload) != 9 + 4 * count:
        raise WindowsTpmReadOnlyError("TPM GetCapability handle list is invalid")
    handles = list(struct.unpack(f">{count}I", payload[9:])) if count else []
    previous = None
    for handle in handles:
        if not TPM_HR_NV_INDEX <= handle <= TPM_HR_NV_INDEX_LAST:
            raise WindowsTpmReadOnlyError("TPM returned a non-NV handle")
        if previous is not None and handle <= previous:
            raise WindowsTpmReadOnlyError("TPM NV handles are not strictly ordered")
        previous = handle
    return bool(more_data), handles


def _parse_tpm2b(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset < 0 or offset + 2 > len(data):
        raise WindowsTpmReadOnlyError("TPM2B response is truncated")
    size = int.from_bytes(data[offset : offset + 2], "big")
    start = offset + 2
    end = start + size
    if end > len(data):
        raise WindowsTpmReadOnlyError("TPM2B response length is invalid")
    return data[start:end], end
def _name_sha256_matches(tpms_nv_public: bytes, raw_name: bytes) -> bool:
    if len(raw_name) != 34 or raw_name[:2] != b"\x00\x0b":
        return False
    return raw_name[2:] == hashlib.sha256(tpms_nv_public).digest()


def _parse_nv_read_public(payload: bytes, *, expected_handle: int) -> dict[str, Any]:
    public, offset = _parse_tpm2b(payload, 0)
    raw_name, offset = _parse_tpm2b(payload, offset)
    if offset != len(payload):
        raise WindowsTpmReadOnlyError("NV_ReadPublic response has trailing bytes")
    parsed = _parse_tpms_nv_public(public)
    if parsed["nv_index"] != expected_handle:
        raise WindowsTpmReadOnlyError("NV_ReadPublic returned another NV index")
    name_verified = False
    if parsed["name_alg"] == TPM_ALG_SHA256:
        name_verified = _name_sha256_matches(public, raw_name)
        if not name_verified:
            raise WindowsTpmReadOnlyError("NV Name does not bind TPMS_NV_PUBLIC")
    attributes = parsed["attributes"]
    nv_type_bits = attributes & TPMA_NV_NT_MASK
    policy = parsed["auth_policy"]
    return {
        "nv_index": expected_handle,
        "name_alg": parsed["name_alg"],
        "tpma_nv_mask": attributes,
        "nv_type_bits": nv_type_bits,
        "nv_type": TPM_NT_NAMES.get(nv_type_bits, f"UNKNOWN_0x{nv_type_bits:02x}"),
        "data_size": parsed["data_size"],
        "orderly": bool(attributes & TPMA_NV_ORDERLY),
        "auth_policy_hex": policy.hex(),
        "auth_policy_sha256": policy.hex() if policy else None,
        "tpms_nv_public_marshaled": public,
        "raw_tpm_name": raw_name,
        "nv_public_sha256": hashlib.sha256(public).hexdigest(),
        "nv_name_sha256": hashlib.sha256(raw_name).hexdigest(),
        "name_verified": name_verified,
    }


def enumerate_nv_handles() -> list[int]:
    """Enumerate all currently defined NV handles via TPM2_GetCapability only."""
    property_value = TPM_HR_NV_INDEX
    result: list[int] = []
    for _ in range(_MAX_DISCOVERY_PAGES):
        parameters = struct.pack(
            ">III", TPM_CAP_HANDLES, property_value, _MAX_HANDLES_PER_PAGE
        )
        more_data, handles = _parse_get_capability_handles(
            _submit_readonly(TPM_CC_GET_CAPABILITY, parameters)
        )
        if handles:
            if result and handles[0] <= result[-1]:
                raise WindowsTpmReadOnlyError("TPM NV discovery pagination regressed")
            result.extend(handles)
        if not more_data:
            return result
        if not handles or handles[-1] == TPM_HR_NV_INDEX_LAST:
            raise WindowsTpmReadOnlyError("TPM NV discovery pagination is inconsistent")
        property_value = handles[-1] + 1
    raise WindowsTpmReadOnlyError("TPM NV discovery exceeded bounded pages")
def read_nv_public(nv_index: int) -> dict[str, Any]:
    """Read and verify one public NV area and TPM Name; no authorization session."""
    if type(nv_index) is not int or not TPM_HR_NV_INDEX <= nv_index <= TPM_HR_NV_INDEX_LAST:
        raise WindowsTpmReadOnlyError("NV handle is outside the TPM NV range")
    payload = _submit_readonly(
        TPM_CC_NV_READ_PUBLIC, struct.pack(">I", nv_index)
    )
    return _parse_nv_read_public(payload, expected_handle=nv_index)


def discover_nv_public() -> list[dict[str, Any]]:
    """Return verified public metadata for every currently defined NV index."""
    return [read_nv_public(handle) for handle in enumerate_nv_handles()]


def public_discovery_record(value: dict[str, Any]) -> dict[str, Any]:
    """Convert one verified public snapshot to JSON-safe evidence."""
    required = {
        "nv_index", "name_alg", "tpma_nv_mask", "nv_type_bits", "nv_type",
        "data_size", "orderly", "auth_policy_hex", "auth_policy_sha256",
        "tpms_nv_public_marshaled", "raw_tpm_name", "nv_public_sha256",
        "nv_name_sha256", "name_verified",
    }
    if type(value) is not dict or set(value) != required:
        raise WindowsTpmReadOnlyError("NV public discovery record schema is invalid")
    return {
        **{key: item for key, item in value.items() if key not in {
            "tpms_nv_public_marshaled", "raw_tpm_name"
        }},
        "nv_index_hex": f"0x{value['nv_index']:08x}",
        "tpms_nv_public_hex": value["tpms_nv_public_marshaled"].hex(),
        "raw_tpm_name_hex": value["raw_tpm_name"].hex(),
    }
