"""Offline-only R15B Windows TPM provisioning ceremony.

This module is intentionally not imported by runtime, MCP, broker, or CLI
surfaces.  It can define exactly one reviewed NV_EXTEND index and perform one
domain-separated primer extend, but only when called with its exact generated
hardware-write authorization token.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
import hashlib
import json
import struct
import sys
from typing import Any, Callable

from .tpm2_provider_binding import (
    BoundTpm2NvExtendProfile,
    Tpm2NvBindingConstraints,
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
    enumerate_nv_handles,
    read_nv_public,
)
from .windows_tpm_runtime import (
    TPM_CC_NV_EXTEND,
    TPM_RS_PW,
    TPM_ST_SESSIONS,
    WindowsTbsNvExtendBackend,
    _require_pw_response,
)

TPM_CC_NV_DEFINE_SPACE = 0x0000012A
TPM_RH_OWNER = 0x40000001
TBS_OWNERAUTH_TYPE_STORAGE_20 = 13

TPMA_NV_AUTHWRITE = 0x00000004
TPMA_NV_NT_EXTEND = 0x00000040
TPMA_NV_AUTHREAD = 0x00040000
TPMA_NV_NO_DA = 0x02000000
TPMA_NV_WRITTEN = 0x20000000

DEFAULT_DEFINITION_MASK = (
    TPMA_NV_AUTHWRITE | TPMA_NV_NT_EXTEND | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA
)
DEFAULT_NV_INDEX = 0x01500020
_BACKEND_KIND = "WINDOWS_TBS_TPM2_NV_V1"
_PRIMER_DOMAIN = "continuityos.r15b.nv-extend-primer.v1"

_ALLOWED_PROVISIONING_COMMANDS = frozenset({
    TPM_CC_NV_DEFINE_SPACE, TPM_CC_NV_EXTEND
})


class WindowsTpmProvisioningError(RuntimeError):
    """Offline provisioning failed closed."""


STATE_EMPTY = "EMPTY"
STATE_CUSTODY_ONLY = "CUSTODY_ONLY"
STATE_DEFINED_UNPRIMED = "DEFINED_UNPRIMED"
STATE_PRIMED_UNVERIFIED = "PRIMED_UNVERIFIED"
STATE_PRIMED_VERIFIED = "PRIMED_VERIFIED"


@dataclass(frozen=True)
class ProvisioningState:
    state: str
    custody_present: bool
    handle_present: bool
    public_phase: str | None
    digest_verified: bool

    def public_receipt(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "custody_present": self.custody_present,
            "handle_present": self.handle_present,
            "public_phase": self.public_phase,
            "digest_verified": self.digest_verified,
        }


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha256(value: str, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise WindowsTpmProvisioningError(f"{label} is invalid")
    return value


def _marshal_nv_public(*, nv_index: int, attributes: int) -> bytes:
    return b"".join((
        nv_index.to_bytes(4, "big"),
        (0x000B).to_bytes(2, "big"),
        attributes.to_bytes(4, "big"),
        (0).to_bytes(2, "big"),
        (32).to_bytes(2, "big"),
    ))


def _raw_name(public: bytes) -> bytes:
    return b"\x00\x0b" + hashlib.sha256(public).digest()


@dataclass(frozen=True)
class WindowsTpmNvProvisioningPlan:
    """Immutable reviewed inputs and predicted post-primer profile."""

    nv_index: int
    ek_public_sha256: str
    definition_mask: int = DEFAULT_DEFINITION_MASK
    backend_kind: str = _BACKEND_KIND

    def __post_init__(self) -> None:
        if type(self.nv_index) is not int or not 0x01000000 <= self.nv_index <= 0x01FFFFFF:
            raise WindowsTpmProvisioningError("provisioning NV index is invalid")
        _require_sha256(self.ek_public_sha256, "provisioning EK identity")
        if self.definition_mask != DEFAULT_DEFINITION_MASK:
            raise WindowsTpmProvisioningError("provisioning TPMA_NV mask is unreviewed")
        if self.backend_kind != _BACKEND_KIND:
            raise WindowsTpmProvisioningError("provisioning backend kind is unreviewed")

    @property
    def active_mask(self) -> int:
        return self.definition_mask | TPMA_NV_WRITTEN

    @property
    def transport_identity(self) -> str:
        return (
            "windows-tbs:v1;locality=0;"
            f"ekpub-sha256={self.ek_public_sha256};"
            "vendor=INTC;fw=403.1.0.0"
        )

    @property
    def definition_public(self) -> bytes:
        return _marshal_nv_public(
            nv_index=self.nv_index, attributes=self.definition_mask
        )

    @property
    def active_public(self) -> bytes:
        return _marshal_nv_public(
            nv_index=self.nv_index, attributes=self.active_mask
        )

    @property
    def primer_document(self) -> dict[str, str]:
        return {
            "domain": _PRIMER_DOMAIN,
            "device_ek_sha256": self.ek_public_sha256,
            "nv_index": f"0x{self.nv_index:08x}",
            "definition_nv_public_sha256": _sha256_hex(self.definition_public),
        }

    @property
    def primer_commitment(self) -> bytes:
        return hashlib.sha256(_canonical(self.primer_document)).digest()

    @property
    def primed_genesis_digest(self) -> str:
        return hashlib.sha256(bytes(32) + self.primer_commitment).hexdigest()

    @property
    def active_profile(self) -> BoundTpm2NvExtendProfile:
        constraints = Tpm2NvBindingConstraints(
            nv_index=self.nv_index,
            tpma_nv_mask=self.active_mask,
            auth_policy_sha256=None,
            backend_kind=self.backend_kind,
            transport_identity=self.transport_identity,
        )
        return BoundTpm2NvExtendProfile(
            constraints=constraints,
            nv_public_sha256=_sha256_hex(self.active_public),
            nv_name_sha256=_sha256_hex(_raw_name(self.active_public)),
            genesis_digest=self.primed_genesis_digest,
        )

    def public_document(self) -> dict[str, Any]:
        profile = self.active_profile
        return {
            "schema": "continuityos.r15b.windows-tpm-provisioning-plan/v1",
            "nv_index": f"0x{self.nv_index:08x}",
            "define_hierarchy": "TPM_RH_OWNER",
            "definition_mask": f"0x{self.definition_mask:08x}",
            "active_mask": f"0x{self.active_mask:08x}",
            "definition_public_sha256": _sha256_hex(self.definition_public),
            "definition_name_sha256": _sha256_hex(_raw_name(self.definition_public)),
            "active_public_sha256": profile.nv_public_sha256,
            "active_name_sha256": profile.nv_name_sha256,
            "primer_sha256": self.primer_commitment.hex(),
            "primed_genesis_digest": self.primed_genesis_digest,
            "backend_kind": self.backend_kind,
            "transport_identity": self.transport_identity,
            "active_profile_binding_sha256": profile.binding_sha256(),
        }

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(_canonical(self.public_document())).hexdigest()

    @property
    def hardware_write_authorization_token(self) -> str:
        return (
            "APPROVE_CONTINUITYOS_R15B_HARDWARE_PROVISION_"
            + self.fingerprint[:16].upper()
        )


def build_reviewed_plan(
    *,
    ek_public_sha256: str,
    nv_index: int = DEFAULT_NV_INDEX,
) -> WindowsTpmNvProvisioningPlan:
    return WindowsTpmNvProvisioningPlan(
        nv_index=nv_index, ek_public_sha256=ek_public_sha256
    )


def _pw_area(auth_value: bytearray) -> bytes:
    if type(auth_value) is not bytearray or not 1 <= len(auth_value) <= 64:
        raise WindowsTpmProvisioningError("provisioning authorization is invalid")
    return b"".join((
        struct.pack(">I", TPM_RS_PW),
        struct.pack(">H", 0),
        b"\x00",
        struct.pack(">H", len(auth_value)),
        bytes(auth_value),
    ))


def _offline_session_command(
    *,
    command_code: int,
    handles: tuple[int, ...],
    auth_value: bytearray,
    parameters: bytes,
) -> bytes:
    if command_code not in _ALLOWED_PROVISIONING_COMMANDS:
        raise WindowsTpmProvisioningError(
            "TPM command is outside offline provisioning allowlist"
        )
    handle_bytes = b"".join(struct.pack(">I", item) for item in handles)
    auth = _pw_area(auth_value)
    body = handle_bytes + struct.pack(">I", len(auth)) + auth + parameters
    return struct.pack(
        ">HII", TPM_ST_SESSIONS, 10 + len(body), command_code
    ) + body


class _OfflineTbsProvisioningTransport:
    """Private transport with only NV_DefineSpace and one NV_Extend primitive."""

    def _submit(self, command: bytes) -> bytes:
        if type(command) is not bytes or len(command) < 10:
            raise WindowsTpmProvisioningError("provisioning TPM command is invalid")
        _, declared_size, command_code = struct.unpack(">HII", command[:10])
        if (
            declared_size != len(command)
            or command_code not in _ALLOWED_PROVISIONING_COMMANDS
        ):
            raise WindowsTpmProvisioningError(
                "provisioning TPM command is outside allowlist"
            )
        dll = _load_tbs()
        params = _TbsContextParams2(TPM_VERSION_20, TBS_CONTEXT_FLAGS)
        context = ctypes.c_void_p()
        result = dll.Tbsi_Context_Create(
            ctypes.byref(params), ctypes.byref(context)
        )
        if result != TBS_SUCCESS or not context.value:
            raise WindowsTpmProvisioningError(
                f"TBS provisioning context failed with 0x{result:08x}"
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
                raise WindowsTpmProvisioningError(
                    f"TBS provisioning submit failed with 0x{result:08x}"
                )
            return _require_pw_response(bytes(out_buffer[: out_size.value]))
        finally:
            close_result = dll.Tbsip_Context_Close(context)
            if close_result != TBS_SUCCESS:
                raise WindowsTpmProvisioningError(
                    f"TBS provisioning close failed with 0x{close_result:08x}"
                )

    def define_space(
        self,
        *,
        owner_auth: bytearray,
        index_auth: bytearray,
        plan: WindowsTpmNvProvisioningPlan,
    ) -> None:
        parameters = (
            struct.pack(">H", len(index_auth))
            + bytes(index_auth)
            + struct.pack(">H", len(plan.definition_public))
            + plan.definition_public
        )
        command = _offline_session_command(
            command_code=TPM_CC_NV_DEFINE_SPACE,
            handles=(TPM_RH_OWNER,),
            auth_value=owner_auth,
            parameters=parameters,
        )
        if self._submit(command) != b"":
            raise WindowsTpmProvisioningError(
                "NV_DefineSpace returned unexpected parameters"
            )

    def primer_extend(
        self,
        *,
        index_auth: bytearray,
        plan: WindowsTpmNvProvisioningPlan,
    ) -> None:
        command = _offline_session_command(
            command_code=TPM_CC_NV_EXTEND,
            handles=(plan.nv_index, plan.nv_index),
            auth_value=index_auth,
            parameters=(
                struct.pack(">H", len(plan.primer_commitment))
                + plan.primer_commitment
            ),
        )
        if self._submit(command) != b"":
            raise WindowsTpmProvisioningError(
                "primer NV_Extend returned unexpected parameters"
            )


def _generate_index_auth_windows() -> bytearray:
    if sys.platform != "win32":
        raise WindowsTpmProvisioningError("Windows CSPRNG requires win32")
    bcrypt = ctypes.WinDLL("bcrypt.dll")
    bcrypt.BCryptGenRandom.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong
    ]
    bcrypt.BCryptGenRandom.restype = ctypes.c_long
    buffer = (ctypes.c_ubyte * 32)()
    status = bcrypt.BCryptGenRandom(None, buffer, 32, 0x00000002)
    if status != 0:
        raise WindowsTpmProvisioningError(
            f"BCryptGenRandom failed with NTSTATUS 0x{status & 0xffffffff:08x}"
        )
    value = bytearray(buffer[:])
    for index in range(len(buffer)):
        buffer[index] = 0
    return value


def _load_storage_owner_auth() -> bytearray:
    dll = _load_tbs()
    dll.Tbsi_Get_OwnerAuth.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    dll.Tbsi_Get_OwnerAuth.restype = ctypes.c_uint32
    params = _TbsContextParams2(TPM_VERSION_20, TBS_CONTEXT_FLAGS)
    context = ctypes.c_void_p()
    result = dll.Tbsi_Context_Create(
        ctypes.byref(params), ctypes.byref(context)
    )
    if result != TBS_SUCCESS or not context.value:
        raise WindowsTpmProvisioningError(
            f"TBS ownerAuth context failed with 0x{result:08x}"
        )
    try:
        length = ctypes.c_uint32(0)
        result = dll.Tbsi_Get_OwnerAuth(
            context, TBS_OWNERAUTH_TYPE_STORAGE_20, None, ctypes.byref(length)
        )
        if result != TBS_SUCCESS or not 1 <= length.value <= 64:
            raise WindowsTpmProvisioningError(
                f"TBS storage ownerAuth unavailable: 0x{result:08x}"
            )
        buffer = (ctypes.c_ubyte * length.value)()
        result = dll.Tbsi_Get_OwnerAuth(
            context,
            TBS_OWNERAUTH_TYPE_STORAGE_20,
            buffer,
            ctypes.byref(length),
        )
        if result != TBS_SUCCESS:
            raise WindowsTpmProvisioningError(
                f"TBS storage ownerAuth read failed: 0x{result:08x}"
            )
        value = bytearray(buffer[: length.value])
        for index in range(len(buffer)):
            buffer[index] = 0
        return value
    finally:
        close_result = dll.Tbsip_Context_Close(context)
        if close_result != TBS_SUCCESS:
            raise WindowsTpmProvisioningError(
                f"TBS ownerAuth close failed with 0x{close_result:08x}"
            )


def _require_public(
    value: dict[str, Any],
    *,
    plan: WindowsTpmNvProvisioningPlan,
    active: bool,
) -> None:
    expected_public = plan.active_public if active else plan.definition_public
    expected_mask = plan.active_mask if active else plan.definition_mask
    if (
        value.get("nv_index") != plan.nv_index
        or value.get("tpma_nv_mask") != expected_mask
        or value.get("nv_type") != "TPM_NT_EXTEND"
        or value.get("data_size") != 32
        or value.get("orderly") is not False
        or value.get("auth_policy_sha256") is not None
        or value.get("tpms_nv_public_marshaled") != expected_public
        or value.get("raw_tpm_name") != _raw_name(expected_public)
        or value.get("name_verified") is not True
    ):
        label = "active" if active else "definition"
        raise WindowsTpmProvisioningError(
            f"{label} NV public identity differs from reviewed plan"
        )


class OfflineWindowsTpmNvProvisioner:
    """Crash-resumable forward-only offline provisioning ceremony."""

    def __init__(
        self,
        *,
        transport: Any | None = None,
        handle_reader: Callable[[], list[int]] | None = None,
        public_reader: Callable[[int], dict[str, Any]] | None = None,
        owner_auth_loader: Callable[[], bytearray] | None = None,
        runtime_backend_factory: Callable[..., Any] | None = None,
        secret_generator: Callable[[], bytearray] | None = None,
    ) -> None:
        self._transport = transport or _OfflineTbsProvisioningTransport()
        self._handle_reader = handle_reader or enumerate_nv_handles
        self._public_reader = public_reader or read_nv_public
        self._owner_auth_loader = owner_auth_loader or _load_storage_owner_auth
        self._runtime_backend_factory = (
            runtime_backend_factory or WindowsTbsNvExtendBackend
        )
        self._secret_generator = secret_generator or _generate_index_auth_windows

    def _active_digest(
        self,
        *,
        plan: WindowsTpmNvProvisioningPlan,
        secret_store: DpapiIndexAuthStore,
    ) -> str:
        backend = self._runtime_backend_factory(secret_store)
        snapshot = backend.read_snapshot(profile=plan.active_profile)
        digest = snapshot.get("observed_nv_extend_digest")
        if type(digest) is not str:
            raise WindowsTpmProvisioningError(
                "active NV digest verification returned an invalid snapshot"
            )
        return digest

    def inspect_state(
        self,
        *,
        plan: WindowsTpmNvProvisioningPlan,
        secret_store: DpapiIndexAuthStore,
    ) -> ProvisioningState:
        """Classify durable custody plus TPM public state without mutation."""
        custody = secret_store.exists()
        handles = self._handle_reader()
        if type(handles) is not list or any(type(item) is not int for item in handles):
            raise WindowsTpmProvisioningError(
                "provisioning handle inventory is invalid"
            )
        present = plan.nv_index in handles
        if not present:
            return ProvisioningState(
                state=STATE_CUSTODY_ONLY if custody else STATE_EMPTY,
                custody_present=custody,
                handle_present=False,
                public_phase=None,
                digest_verified=False,
            )
        if not custody:
            raise WindowsTpmProvisioningError(
                "reviewed NV index exists without matching DPAPI custody"
            )

        public = self._public_reader(plan.nv_index)
        try:
            _require_public(public, plan=plan, active=False)
        except WindowsTpmProvisioningError:
            pass
        else:
            return ProvisioningState(
                state=STATE_DEFINED_UNPRIMED,
                custody_present=True,
                handle_present=True,
                public_phase="DEFINITION",
                digest_verified=False,
            )

        try:
            _require_public(public, plan=plan, active=True)
        except WindowsTpmProvisioningError as exc:
            raise WindowsTpmProvisioningError(
                "existing NV public identity is outside reviewed provisioning states"
            ) from exc

        try:
            digest = self._active_digest(plan=plan, secret_store=secret_store)
        except Exception:
            return ProvisioningState(
                state=STATE_PRIMED_UNVERIFIED,
                custody_present=True,
                handle_present=True,
                public_phase="ACTIVE",
                digest_verified=False,
            )
        if digest != plan.primed_genesis_digest:
            raise WindowsTpmProvisioningError(
                "active NV digest differs from reviewed primed genesis"
            )
        return ProvisioningState(
            state=STATE_PRIMED_VERIFIED,
            custody_present=True,
            handle_present=True,
            public_phase="ACTIVE",
            digest_verified=True,
        )

    def _create_custody(
        self, *, secret_store: DpapiIndexAuthStore
    ) -> None:
        index_auth = self._secret_generator()
        if type(index_auth) is not bytearray or len(index_auth) != 32:
            raise WindowsTpmProvisioningError(
                "index auth generator must return exactly 32 mutable bytes"
            )
        try:
            secret_store.store_once(index_auth)
        finally:
            zeroize(index_auth)

    def _define_from_custody(
        self,
        *,
        plan: WindowsTpmNvProvisioningPlan,
        secret_store: DpapiIndexAuthStore,
    ) -> None:
        index_auth = secret_store.load()
        try:
            owner_auth = self._owner_auth_loader()
            try:
                self._transport.define_space(
                    owner_auth=owner_auth,
                    index_auth=index_auth,
                    plan=plan,
                )
            finally:
                zeroize(owner_auth)
        finally:
            zeroize(index_auth)

    def _primer_from_custody(
        self,
        *,
        plan: WindowsTpmNvProvisioningPlan,
        secret_store: DpapiIndexAuthStore,
    ) -> None:
        index_auth = secret_store.load()
        try:
            self._transport.primer_extend(
                index_auth=index_auth, plan=plan
            )
        finally:
            zeroize(index_auth)

    def _verified_receipt(
        self, *, plan: WindowsTpmNvProvisioningPlan
    ) -> dict[str, Any]:
        return {
            **plan.public_document(),
            "plan_fingerprint": plan.fingerprint,
            "provisioning_state": STATE_PRIMED_VERIFIED,
            "result": "PRIMED_PROFILE_READY",
        }

    def resume_provisioning(
        self,
        *,
        plan: WindowsTpmNvProvisioningPlan,
        secret_store: DpapiIndexAuthStore,
        authorization_token: str,
    ) -> dict[str, Any]:
        """Resume only forward from durable facts; never rollback or repeat a step."""
        if authorization_token != plan.hardware_write_authorization_token:
            raise WindowsTpmProvisioningError(
                "hardware provisioning authorization token mismatch"
            )

        for _ in range(4):
            state = self.inspect_state(plan=plan, secret_store=secret_store)
            if state.state == STATE_PRIMED_VERIFIED:
                return self._verified_receipt(plan=plan)
            if state.state == STATE_PRIMED_UNVERIFIED:
                digest = self._active_digest(
                    plan=plan, secret_store=secret_store
                )
                if digest != plan.primed_genesis_digest:
                    raise WindowsTpmProvisioningError(
                        "active NV digest differs from reviewed primed genesis"
                    )
                return self._verified_receipt(plan=plan)
            if state.state == STATE_EMPTY:
                self._create_custody(secret_store=secret_store)
                continue
            if state.state == STATE_CUSTODY_ONLY:
                self._define_from_custody(
                    plan=plan, secret_store=secret_store
                )
                continue
            if state.state == STATE_DEFINED_UNPRIMED:
                self._primer_from_custody(
                    plan=plan, secret_store=secret_store
                )
                continue
            raise WindowsTpmProvisioningError(
                "provisioning state is not resumable"
            )
        raise WindowsTpmProvisioningError(
            "provisioning did not converge within bounded transitions"
        )

    def provision_once(
        self,
        *,
        plan: WindowsTpmNvProvisioningPlan,
        secret_store: DpapiIndexAuthStore,
        authorization_token: str,
    ) -> dict[str, Any]:
        """Compatibility alias for the crash-resumable forward-only ceremony."""
        return self.resume_provisioning(
            plan=plan,
            secret_store=secret_store,
            authorization_token=authorization_token,
        )
