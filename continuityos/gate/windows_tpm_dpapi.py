"""Windows DPAPI custody for one R15B TPM NV index authorization secret.

This module never provisions or talks to the TPM.  It stores only a DPAPI-
protected 32-byte index authValue plus public binding metadata.  Plaintext
secret bytes are returned only as a mutable bytearray so callers can zero them.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any, Protocol

_SCHEMA = "continuityos.r15b.windows-dpapi-index-auth/v1"
_ENTROPY_DOMAIN = b"continuityos.r15b.windows-dpapi-index-auth/v1\0"
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


class WindowsDpapiCustodyError(RuntimeError):
    """DPAPI custody is unavailable, corrupt, or bound to another profile."""


class _Protector(Protocol):
    def protect(self, plaintext: bytearray, *, entropy: bytes) -> bytes: ...
    def unprotect(self, ciphertext: bytes, *, entropy: bytes) -> bytearray: ...


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint32),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def zeroize(value: bytearray) -> None:
    """Best-effort in-place zeroization for mutable secret buffers."""
    if type(value) is not bytearray:
        raise TypeError("zeroize requires bytearray")
    for index in range(len(value)):
        value[index] = 0


def _require_windows() -> None:
    if sys.platform != "win32":
        raise WindowsDpapiCustodyError("Windows DPAPI requires win32")


def _entropy(*, nv_index: int, ek_public_sha256: str) -> bytes:
    if type(nv_index) is not int or not 0x01000000 <= nv_index <= 0x01FFFFFF:
        raise WindowsDpapiCustodyError("DPAPI NV index is invalid")
    if (
        type(ek_public_sha256) is not str
        or len(ek_public_sha256) != 64
        or any(ch not in "0123456789abcdef" for ch in ek_public_sha256)
    ):
        raise WindowsDpapiCustodyError("DPAPI EK identity is invalid")
    return hashlib.sha256(
        _ENTROPY_DOMAIN
        + nv_index.to_bytes(4, "big")
        + bytes.fromhex(ek_public_sha256)
    ).digest()


def _blob_from_bytes(value: bytes | bytearray) -> tuple[_DataBlob, Any]:
    if not value:
        return _DataBlob(0, None), None
    if type(value) is bytearray:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer(value)
    else:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    return _DataBlob(len(value), buffer), buffer


def _copy_blob(value: _DataBlob) -> bytes:
    if value.cbData == 0:
        return b""
    if not value.pbData:
        raise WindowsDpapiCustodyError("DPAPI returned an invalid blob")
    return bytes(ctypes.string_at(value.pbData, value.cbData))


class _WindowsDpapiProtector:
    def _crypt32(self):
        _require_windows()
        try:
            dll = ctypes.WinDLL("crypt32.dll")
            kernel = ctypes.WinDLL("kernel32.dll")
        except Exception as exc:
            raise WindowsDpapiCustodyError("Windows DPAPI DLLs are unavailable") from exc
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        return dll, kernel

    def protect(self, plaintext: bytearray, *, entropy: bytes) -> bytes:
        if type(plaintext) is not bytearray or len(plaintext) != 32:
            raise WindowsDpapiCustodyError("index authValue must be exactly 32 bytes")
        dll, kernel = self._crypt32()
        dll.CryptProtectData.argtypes = [
            ctypes.POINTER(_DataBlob), ctypes.c_wchar_p,
            ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.POINTER(_DataBlob),
        ]
        dll.CryptProtectData.restype = ctypes.c_bool
        input_blob, input_keepalive = _blob_from_bytes(plaintext)
        entropy_blob, entropy_keepalive = _blob_from_bytes(entropy)
        output = _DataBlob()
        try:
            ok = dll.CryptProtectData(
                ctypes.byref(input_blob), None, ctypes.byref(entropy_blob),
                None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output),
            )
            if not ok:
                raise WindowsDpapiCustodyError(
                    f"CryptProtectData failed with WinError {ctypes.get_last_error()}"
                )
            return _copy_blob(output)
        finally:
            _ = input_keepalive, entropy_keepalive
            if output.pbData:
                kernel.LocalFree(output.pbData)

    def unprotect(self, ciphertext: bytes, *, entropy: bytes) -> bytearray:
        if type(ciphertext) is not bytes or not ciphertext:
            raise WindowsDpapiCustodyError("DPAPI ciphertext is invalid")
        dll, kernel = self._crypt32()
        dll.CryptUnprotectData.argtypes = [
            ctypes.POINTER(_DataBlob), ctypes.c_void_p,
            ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.POINTER(_DataBlob),
        ]
        dll.CryptUnprotectData.restype = ctypes.c_bool
        input_blob, input_keepalive = _blob_from_bytes(ciphertext)
        entropy_blob, entropy_keepalive = _blob_from_bytes(entropy)
        output = _DataBlob()
        try:
            ok = dll.CryptUnprotectData(
                ctypes.byref(input_blob), None, ctypes.byref(entropy_blob),
                None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output),
            )
            if not ok:
                raise WindowsDpapiCustodyError(
                    f"CryptUnprotectData failed with WinError {ctypes.get_last_error()}"
                )
            plaintext = bytearray(_copy_blob(output))
            if len(plaintext) != 32:
                zeroize(plaintext)
                raise WindowsDpapiCustodyError("DPAPI plaintext length is invalid")
            return plaintext
        finally:
            _ = input_keepalive, entropy_keepalive
            if output.pbData:
                kernel.LocalFree(output.pbData)


class DpapiIndexAuthStore:
    """Persist one DPAPI-protected index authValue with exact public binding."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        nv_index: int,
        ek_public_sha256: str,
        protector: _Protector | None = None,
    ) -> None:
        self.path = Path(path)
        self.nv_index = nv_index
        self.ek_public_sha256 = ek_public_sha256
        self._entropy = _entropy(
            nv_index=nv_index, ek_public_sha256=ek_public_sha256
        )
        self._protector = protector or _WindowsDpapiProtector()

    def exists(self) -> bool:
        return self.path.is_file()

    def _envelope(self, ciphertext: bytes) -> dict[str, Any]:
        return {
            "schema": _SCHEMA,
            "provider": "WINDOWS_DPAPI_CURRENT_USER",
            "nv_index": self.nv_index,
            "ek_public_sha256": self.ek_public_sha256,
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        }

    def store_once(self, secret: bytearray) -> None:
        if type(secret) is not bytearray or len(secret) != 32:
            raise WindowsDpapiCustodyError("index authValue must be exactly 32 bytes")
        if self.exists():
            raise WindowsDpapiCustodyError("DPAPI custody file already exists")
        ciphertext = self._protector.protect(secret, entropy=self._entropy)
        payload = json.dumps(
            self._envelope(ciphertext),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(
            f".{self.path.name}.{secrets.token_hex(8)}.tmp"
        )
        try:
            with open(temporary, "xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def load(self) -> bytearray:
        try:
            payload = json.loads(self.path.read_text(encoding="ascii"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise WindowsDpapiCustodyError("DPAPI custody envelope is unreadable") from exc
        expected = {
            "schema", "provider", "nv_index", "ek_public_sha256", "ciphertext_b64"
        }
        if type(payload) is not dict or set(payload) != expected:
            raise WindowsDpapiCustodyError("DPAPI custody envelope schema is invalid")
        if (
            payload["schema"] != _SCHEMA
            or payload["provider"] != "WINDOWS_DPAPI_CURRENT_USER"
            or payload["nv_index"] != self.nv_index
            or payload["ek_public_sha256"] != self.ek_public_sha256
        ):
            raise WindowsDpapiCustodyError("DPAPI custody binding differs")
        try:
            ciphertext = base64.b64decode(
                payload["ciphertext_b64"], validate=True
            )
        except (TypeError, ValueError) as exc:
            raise WindowsDpapiCustodyError("DPAPI ciphertext encoding is invalid") from exc
        return self._protector.unprotect(ciphertext, entropy=self._entropy)
