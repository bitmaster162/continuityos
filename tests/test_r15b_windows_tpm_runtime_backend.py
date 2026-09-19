"""Hardware-free tests for the R15B Windows TBS backend and provisioning ceremony."""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import struct

import pytest

from continuityos.gate import windows_tpm_runtime as runtime
from continuityos.gate.windows_tpm_dpapi import (
    DpapiIndexAuthStore,
    WindowsDpapiCustodyError,
)
from continuityos.gate.windows_tpm_provisioning import (
    OfflineWindowsTpmNvProvisioner,
    WindowsTpmProvisioningError,
    build_reviewed_plan,
)


EK_SHA256 = "d4493341ea776e196234af9547d2a22118767eea3a0312d00e445fa497f6469c"


class FakeProtector:
    def protect(self, plaintext: bytearray, *, entropy: bytes) -> bytes:
        assert len(entropy) == 32
        return bytes(item ^ entropy[index % len(entropy)] for index, item in enumerate(plaintext))

    def unprotect(self, ciphertext: bytes, *, entropy: bytes) -> bytearray:
        assert len(entropy) == 32
        return bytearray(
            item ^ entropy[index % len(entropy)]
            for index, item in enumerate(ciphertext)
        )


def test_dpapi_store_persists_ciphertext_only_and_binds_context(tmp_path) -> None:
    path = tmp_path / "r15b.dpapi.json"
    secret = bytearray(range(32))
    store = DpapiIndexAuthStore(
        path,
        nv_index=0x01500020,
        ek_public_sha256=EK_SHA256,
        protector=FakeProtector(),
    )
    store.store_once(secret)
    text = path.read_text(encoding="ascii")
    assert secret.hex() not in text
    assert base64.b64encode(bytes(secret)).decode("ascii") not in text
    loaded = store.load()
    assert loaded == secret

    other = DpapiIndexAuthStore(
        path,
        nv_index=0x01500021,
        ek_public_sha256=EK_SHA256,
        protector=FakeProtector(),
    )
    with pytest.raises(WindowsDpapiCustodyError, match="binding differs"):
        other.load()
    with pytest.raises(WindowsDpapiCustodyError, match="already exists"):
        store.store_once(secret)


def public_record(plan, *, active: bool) -> dict:
    public = plan.active_public if active else plan.definition_public
    attrs = plan.active_mask if active else plan.definition_mask
    raw_name = b"\x00\x0b" + hashlib.sha256(public).digest()
    return {
        "nv_index": plan.nv_index,
        "name_alg": 0x000B,
        "tpma_nv_mask": attrs,
        "nv_type_bits": 0x40,
        "nv_type": "TPM_NT_EXTEND",
        "data_size": 32,
        "orderly": False,
        "auth_policy_hex": "",
        "auth_policy_sha256": None,
        "tpms_nv_public_marshaled": public,
        "raw_tpm_name": raw_name,
        "nv_public_sha256": hashlib.sha256(public).hexdigest(),
        "nv_name_sha256": hashlib.sha256(raw_name).hexdigest(),
        "name_verified": True,
    }


class FakeSecretStore:
    def __init__(self, value: bytes = b"s" * 32):
        self.value = bytes(value)
        self.loads: list[bytearray] = []

    def load(self) -> bytearray:
        result = bytearray(self.value)
        self.loads.append(result)
        return result


class FakeRuntimeTransport:
    def __init__(self, digest: str):
        self.digest = digest
        self.read_calls = 0
        self.extend_calls = 0

    def nv_read(self, *, nv_index: int, auth_value: bytearray) -> bytes:
        assert nv_index == 0x01500020
        assert bytes(auth_value) == b"s" * 32
        self.read_calls += 1
        return bytes.fromhex(self.digest)

    def nv_extend(
        self, *, nv_index: int, auth_value: bytearray, commitment: bytes
    ) -> None:
        assert nv_index == 0x01500020
        assert bytes(auth_value) == b"s" * 32
        self.extend_calls += 1
        self.digest = hashlib.sha256(
            bytes.fromhex(self.digest) + commitment
        ).hexdigest()


def test_runtime_backend_reads_extends_and_zeroizes_secret_buffers() -> None:
    plan = build_reviewed_plan(ek_public_sha256=EK_SHA256)
    store = FakeSecretStore()
    transport = FakeRuntimeTransport(plan.primed_genesis_digest)
    backend = runtime.WindowsTbsNvExtendBackend(
        store,
        transport=transport,
        public_reader=lambda handle: public_record(plan, active=True),
    )
    profile = plan.active_profile
    before = backend.read_snapshot(profile=profile)
    assert before["observed_nv_extend_digest"] == plan.primed_genesis_digest
    assert all(set(secret) == {0} for secret in store.loads)

    commitment = "ab" * 32
    after = backend.extend_once(
        profile=profile,
        expected_previous_digest=plan.primed_genesis_digest,
        commitment_sha256=commitment,
    )
    expected = hashlib.sha256(
        bytes.fromhex(plan.primed_genesis_digest)
        + bytes.fromhex(commitment)
    ).hexdigest()
    assert after["observed_nv_extend_digest"] == expected
    assert after["tpma_nv_mask"] == plan.active_mask
    assert transport.extend_calls == 1
    assert all(set(secret) == {0} for secret in store.loads)


def test_runtime_module_exposes_no_provisioning_or_owner_auth_surface() -> None:
    public_names = {name for name in dir(runtime) if not name.startswith("_")}
    forbidden = {
        "OfflineWindowsTpmNvProvisioner",
        "TPM_CC_NV_DEFINE_SPACE",
        "TPM_CC_CLEAR",
        "TPM_CC_NV_UNDEFINE_SPACE",
        "load_storage_owner_auth",
    }
    assert public_names.isdisjoint(forbidden)
    source = inspect.getsource(runtime)
    assert "windows_tpm_provisioning" not in source
    assert "Tbsi_Get_OwnerAuth" not in source


class FakeProvisioningSecretStore:
    def __init__(self):
        self.stored: bytes | None = None
        self.loads: list[bytearray] = []

    def exists(self) -> bool:
        return self.stored is not None

    def store_once(self, secret: bytearray) -> None:
        assert self.stored is None
        self.stored = bytes(secret)

    def load(self) -> bytearray:
        assert self.stored is not None
        value = bytearray(self.stored)
        self.loads.append(value)
        return value


class FakeProvisioningTransport:
    def __init__(self, store: FakeProvisioningSecretStore):
        self.store = store
        self.defined = False
        self.primed = False
        self.calls: list[str] = []

    def define_space(self, *, owner_auth, index_auth, plan) -> None:
        assert self.store.stored == bytes(index_auth)
        assert bytes(owner_auth) == b"o" * 20
        assert len(index_auth) == 32
        self.calls.append("define")
        self.defined = True

    def primer_extend(self, *, index_auth, plan) -> None:
        assert self.defined
        assert bytes(index_auth) == self.store.stored
        assert len(plan.primer_commitment) == 32
        self.calls.append("primer")
        self.primed = True


class FakePostPrimerBackend:
    def __init__(self, plan, store):
        self.plan = plan
        self.store = store

    def read_snapshot(self, *, profile):
        assert profile.binding_sha256() == self.plan.active_profile.binding_sha256()
        return {
            "observed_nv_extend_digest": self.plan.primed_genesis_digest
        }


def test_offline_provisioner_requires_exact_token_and_orders_custody_before_define() -> None:
    plan = build_reviewed_plan(ek_public_sha256=EK_SHA256)
    store = FakeProvisioningSecretStore()
    transport = FakeProvisioningTransport(store)

    def public_reader(_handle):
        if transport.primed:
            return public_record(plan, active=True)
        if transport.defined:
            return public_record(plan, active=False)
        raise AssertionError("public read before definition")

    provisioner = OfflineWindowsTpmNvProvisioner(
        transport=transport,
        handle_reader=lambda: [plan.nv_index] if transport.defined else [],
        public_reader=public_reader,
        owner_auth_loader=lambda: bytearray(b"o" * 20),
        runtime_backend_factory=lambda secret_store: FakePostPrimerBackend(
            plan, secret_store
        ),
        secret_generator=lambda: bytearray(b"s" * 32),
    )
    with pytest.raises(
        WindowsTpmProvisioningError, match="authorization token mismatch"
    ):
        provisioner.provision_once(
            plan=plan, secret_store=store, authorization_token="NO"
        )
    assert transport.calls == []
    assert store.stored is None

    result = provisioner.provision_once(
        plan=plan,
        secret_store=store,
        authorization_token=plan.hardware_write_authorization_token,
    )
    assert transport.calls == ["define", "primer"]
    assert result["result"] == "PRIMED_PROFILE_READY"
    assert result["active_profile_binding_sha256"] == (
        plan.active_profile.binding_sha256()
    )


def test_plan_pins_reviewed_owner_created_profile_and_stable_written_identity() -> None:
    plan = build_reviewed_plan(ek_public_sha256=EK_SHA256)
    assert plan.nv_index == 0x01500020
    assert plan.definition_mask == 0x02040044
    assert plan.active_mask == 0x22040044
    assert hashlib.sha256(plan.definition_public).hexdigest() == (
        "27b26b0e2f7a5f11d63615367817fbbd52410c778e78bfd0c66adc88f9d6d103"
    )
    assert plan.active_profile.nv_public_sha256 == (
        "4e6f663d09b9af433074e55b967ba1f201c5e34c8db8eee7a7ae372855642063"
    )
    assert plan.active_profile.nv_name_sha256 == (
        "5f350a71c3e0946639146d182d5f345d1e7203824a77fcd29cbf654fcc110fc5"
    )
    assert plan.primer_commitment.hex() == (
        "db5a5fa1867e616716b0c3d34e94a87a58c53875f9d5e11b9782756545074ec0"
    )
    assert plan.primed_genesis_digest == (
        "54d69bcdee19684366afcc77cf894482b81fc0864e9b43d769adc020632147e4"
    )
    assert plan.active_profile.binding_sha256() == (
        "d732c991382a2edb99b9dcb39063224c2a62df2c56813668e76a74444c2965d4"
    )


def test_plan_public_document_contains_no_secret_material() -> None:
    plan = build_reviewed_plan(ek_public_sha256=EK_SHA256)
    document = plan.public_document()
    encoded = json.dumps(document, sort_keys=True)
    assert "authValue" not in encoded
    assert "ownerAuth" not in encoded
    assert "ciphertext" not in encoded
    assert plan.hardware_write_authorization_token.startswith(
        "APPROVE_CONTINUITYOS_R15B_HARDWARE_PROVISION_"
    )


class CrashAwareTransport(FakeProvisioningTransport):
    def __init__(self, store, *, fail_after_define=False, fail_after_primer=False):
        super().__init__(store)
        self.fail_after_define = fail_after_define
        self.fail_after_primer = fail_after_primer
        self.define_attempts = 0
        self.primer_attempts = 0

    def define_space(self, *, owner_auth, index_auth, plan) -> None:
        self.define_attempts += 1
        super().define_space(
            owner_auth=owner_auth, index_auth=index_auth, plan=plan
        )
        if self.fail_after_define:
            self.fail_after_define = False
            raise RuntimeError("lost response after define")

    def primer_extend(self, *, index_auth, plan) -> None:
        self.primer_attempts += 1
        super().primer_extend(index_auth=index_auth, plan=plan)
        if self.fail_after_primer:
            self.fail_after_primer = False
            raise RuntimeError("lost response after primer")


def recovery_fixture(*, state: str, fail_after_define=False, fail_after_primer=False):
    from continuityos.gate.windows_tpm_provisioning import (
        STATE_CUSTODY_ONLY,
        STATE_DEFINED_UNPRIMED,
        STATE_EMPTY,
        STATE_PRIMED_VERIFIED,
    )

    plan = build_reviewed_plan(ek_public_sha256=EK_SHA256)
    store = FakeProvisioningSecretStore()
    transport = CrashAwareTransport(
        store,
        fail_after_define=fail_after_define,
        fail_after_primer=fail_after_primer,
    )

    if state != STATE_EMPTY:
        store.stored = b"s" * 32
    if state in {STATE_DEFINED_UNPRIMED, STATE_PRIMED_VERIFIED}:
        transport.defined = True
    if state == STATE_PRIMED_VERIFIED:
        transport.primed = True

    def handles():
        return [plan.nv_index] if transport.defined else []

    def public_reader(_handle):
        assert transport.defined
        return public_record(plan, active=transport.primed)

    provisioner = OfflineWindowsTpmNvProvisioner(
        transport=transport,
        handle_reader=handles,
        public_reader=public_reader,
        owner_auth_loader=lambda: bytearray(b"o" * 20),
        runtime_backend_factory=lambda secret_store: FakePostPrimerBackend(
            plan, secret_store
        ),
        secret_generator=lambda: bytearray(b"s" * 32),
    )
    return plan, store, transport, provisioner


def test_resume_from_custody_only_reuses_secret_and_never_regenerates() -> None:
    from continuityos.gate.windows_tpm_provisioning import STATE_CUSTODY_ONLY

    plan, store, transport, provisioner = recovery_fixture(
        state=STATE_CUSTODY_ONLY
    )
    original = store.stored
    result = provisioner.resume_provisioning(
        plan=plan,
        secret_store=store,
        authorization_token=plan.hardware_write_authorization_token,
    )
    assert result["provisioning_state"] == "PRIMED_VERIFIED"
    assert store.stored == original
    assert transport.define_attempts == 1
    assert transport.primer_attempts == 1


def test_resume_from_defined_unprimed_never_redefines() -> None:
    from continuityos.gate.windows_tpm_provisioning import STATE_DEFINED_UNPRIMED

    plan, store, transport, provisioner = recovery_fixture(
        state=STATE_DEFINED_UNPRIMED
    )
    result = provisioner.resume_provisioning(
        plan=plan,
        secret_store=store,
        authorization_token=plan.hardware_write_authorization_token,
    )
    assert result["provisioning_state"] == "PRIMED_VERIFIED"
    assert transport.define_attempts == 0
    assert transport.primer_attempts == 1


def test_resume_from_primed_verified_performs_no_tpm_mutation() -> None:
    from continuityos.gate.windows_tpm_provisioning import STATE_PRIMED_VERIFIED

    plan, store, transport, provisioner = recovery_fixture(
        state=STATE_PRIMED_VERIFIED
    )
    result = provisioner.resume_provisioning(
        plan=plan,
        secret_store=store,
        authorization_token=plan.hardware_write_authorization_token,
    )
    assert result["result"] == "PRIMED_PROFILE_READY"
    assert transport.define_attempts == 0
    assert transport.primer_attempts == 0


def test_lost_define_response_resumes_without_second_define() -> None:
    from continuityos.gate.windows_tpm_provisioning import STATE_EMPTY

    plan, store, transport, provisioner = recovery_fixture(
        state=STATE_EMPTY, fail_after_define=True
    )
    with pytest.raises(RuntimeError, match="lost response after define"):
        provisioner.resume_provisioning(
            plan=plan,
            secret_store=store,
            authorization_token=plan.hardware_write_authorization_token,
        )
    assert store.exists()
    assert transport.defined
    assert transport.define_attempts == 1
    assert transport.primer_attempts == 0

    result = provisioner.resume_provisioning(
        plan=plan,
        secret_store=store,
        authorization_token=plan.hardware_write_authorization_token,
    )
    assert result["provisioning_state"] == "PRIMED_VERIFIED"
    assert transport.define_attempts == 1
    assert transport.primer_attempts == 1


def test_lost_primer_response_resumes_without_second_primer() -> None:
    from continuityos.gate.windows_tpm_provisioning import STATE_EMPTY

    plan, store, transport, provisioner = recovery_fixture(
        state=STATE_EMPTY, fail_after_primer=True
    )
    with pytest.raises(RuntimeError, match="lost response after primer"):
        provisioner.resume_provisioning(
            plan=plan,
            secret_store=store,
            authorization_token=plan.hardware_write_authorization_token,
        )
    assert transport.defined
    assert transport.primed
    assert transport.define_attempts == 1
    assert transport.primer_attempts == 1

    result = provisioner.resume_provisioning(
        plan=plan,
        secret_store=store,
        authorization_token=plan.hardware_write_authorization_token,
    )
    assert result["provisioning_state"] == "PRIMED_VERIFIED"
    assert transport.define_attempts == 1
    assert transport.primer_attempts == 1


def test_existing_handle_without_custody_is_hard_hold() -> None:
    plan = build_reviewed_plan(ek_public_sha256=EK_SHA256)
    store = FakeProvisioningSecretStore()
    transport = FakeProvisioningTransport(store)
    transport.defined = True
    provisioner = OfflineWindowsTpmNvProvisioner(
        transport=transport,
        handle_reader=lambda: [plan.nv_index],
        public_reader=lambda handle: public_record(plan, active=False),
        owner_auth_loader=lambda: bytearray(b"o" * 20),
        runtime_backend_factory=lambda secret_store: FakePostPrimerBackend(
            plan, secret_store
        ),
        secret_generator=lambda: bytearray(b"s" * 32),
    )
    with pytest.raises(
        WindowsTpmProvisioningError, match="exists without matching DPAPI custody"
    ):
        provisioner.resume_provisioning(
            plan=plan,
            secret_store=store,
            authorization_token=plan.hardware_write_authorization_token,
        )
    assert transport.calls == []


def test_unreviewed_existing_public_identity_is_hard_hold() -> None:
    plan, store, transport, _ = recovery_fixture(state="DEFINED_UNPRIMED")
    bad = public_record(plan, active=False)
    bad["tpma_nv_mask"] ^= 0x1
    provisioner = OfflineWindowsTpmNvProvisioner(
        transport=transport,
        handle_reader=lambda: [plan.nv_index],
        public_reader=lambda handle: bad,
        owner_auth_loader=lambda: bytearray(b"o" * 20),
        runtime_backend_factory=lambda secret_store: FakePostPrimerBackend(
            plan, secret_store
        ),
        secret_generator=lambda: bytearray(b"s" * 32),
    )
    with pytest.raises(
        WindowsTpmProvisioningError,
        match="outside reviewed provisioning states",
    ):
        provisioner.resume_provisioning(
            plan=plan,
            secret_store=store,
            authorization_token=plan.hardware_write_authorization_token,
        )
    assert transport.calls == []


def test_active_wrong_digest_is_hard_hold_without_repeat_primer() -> None:
    from continuityos.gate.windows_tpm_provisioning import STATE_PRIMED_VERIFIED

    plan, store, transport, _ = recovery_fixture(
        state=STATE_PRIMED_VERIFIED
    )

    class WrongDigestBackend:
        def read_snapshot(self, *, profile):
            return {"observed_nv_extend_digest": "11" * 32}

    provisioner = OfflineWindowsTpmNvProvisioner(
        transport=transport,
        handle_reader=lambda: [plan.nv_index],
        public_reader=lambda handle: public_record(plan, active=True),
        owner_auth_loader=lambda: bytearray(b"o" * 20),
        runtime_backend_factory=lambda secret_store: WrongDigestBackend(),
        secret_generator=lambda: bytearray(b"s" * 32),
    )
    with pytest.raises(
        WindowsTpmProvisioningError, match="differs from reviewed primed genesis"
    ):
        provisioner.resume_provisioning(
            plan=plan,
            secret_store=store,
            authorization_token=plan.hardware_write_authorization_token,
        )
    assert transport.define_attempts == 0
    assert transport.primer_attempts == 0


def test_primed_unverified_retries_verification_only() -> None:
    from continuityos.gate.windows_tpm_provisioning import STATE_PRIMED_VERIFIED

    plan, store, transport, _ = recovery_fixture(
        state=STATE_PRIMED_VERIFIED
    )
    calls = {"count": 0}

    class FlakyBackend:
        def read_snapshot(self, *, profile):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("transient read failure")
            return {"observed_nv_extend_digest": plan.primed_genesis_digest}

    provisioner = OfflineWindowsTpmNvProvisioner(
        transport=transport,
        handle_reader=lambda: [plan.nv_index],
            secret_store=store,
            authorization_token=plan.hardware_write_authorization_token,
        )
    assert transport.define_attempts == 0
    assert transport.primer_attempts == 0


def test_primed_unverified_retries_verification_only() -> None:
    from continuityos.gate.windows_tpm_provisioning import STATE_PRIMED_VERIFIED

    plan, store, transport, _ = recovery_fixture(
        state=STATE_PRIMED_VERIFIED
    )
    calls = {"count": 0}
    class FlakyBackend:
        def read_snapshot(self, *, profile):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("transient read failure")
            return {"observed_nv_extend_digest": plan.primed_genesis_digest}

    provisioner = OfflineWindowsTpmNvProvisioner(
        transport=transport,
        handle_reader=lambda: [plan.nv_index],
        public_reader=lambda handle: public_record(plan, active=True),
        owner_auth_loader=lambda: bytearray(b"o" * 20),
        runtime_backend_factory=lambda secret_store: FlakyBackend(),
        secret_generator=lambda: bytearray(b"s" * 32),
    )
    result = provisioner.resume_provisioning(
        plan=plan,
        secret_store=store,
        authorization_token=plan.hardware_write_authorization_token,
    )
    assert result["provisioning_state"] == "PRIMED_VERIFIED"
    assert calls["count"] == 2
    assert transport.define_attempts == 0
    assert transport.primer_attempts == 0


def _pw_response(*, parameters: bytes, attrs: int) -> bytes:
    auth = b"\x00\x00" + bytes([attrs]) + b"\x00\x00"
    total = 10 + 4 + len(parameters) + len(auth)
    return (
        struct.pack(">HII", runtime.TPM_ST_SESSIONS, total, 0)
        + struct.pack(">I", len(parameters))
        + parameters
        + auth
    )


def test_pw_response_accepts_observed_continue_session_attribute() -> None:
    parameters = b"\x00\x20" + bytes.fromhex("54d69bcdee19684366afcc77cf894482b81fc0864e9b43d769adc020632147e4")
    raw = _pw_response(
        parameters=parameters,
        attrs=runtime.TPMA_SESSION_CONTINUESESSION,
    )
    assert raw[-5:].hex() == "0000010000"
    assert runtime._require_pw_response(raw) == parameters


def test_pw_response_accepts_zero_session_attribute() -> None:
    parameters = b"ok"
    raw = _pw_response(parameters=parameters, attrs=0)
    assert runtime._require_pw_response(raw) == parameters


@pytest.mark.parametrize("attrs", [0x02, 0x20, 0x80, 0xFF])
def test_pw_response_rejects_unreviewed_session_attribute_bits(attrs: int) -> None:
    raw = _pw_response(parameters=b"", attrs=attrs)
    with pytest.raises(
        runtime.WindowsTpmRuntimeError,
        match="password response auth area is invalid",
    ):
        runtime._require_pw_response(raw)


def test_pw_response_rejects_nonempty_nonce_or_hmac() -> None:
    parameters = b""
    nonce_auth = b"\x00\x01x\x01\x00\x00"
    total = 10 + 4 + len(nonce_auth)
    raw = (
        struct.pack(">HII", runtime.TPM_ST_SESSIONS, total, 0)
        + struct.pack(">I", 0)
        + nonce_auth
    )
    with pytest.raises(
        runtime.WindowsTpmRuntimeError,
        match="password response auth area is invalid",
    ):
        runtime._require_pw_response(raw)

    hmac_auth = b"\x00\x00\x01\x00\x01x"
    total = 10 + 4 + len(hmac_auth)
    raw = (
        struct.pack(">HII", runtime.TPM_ST_SESSIONS, total, 0)
        + struct.pack(">I", 0)
        + hmac_auth
    )
    with pytest.raises(
        runtime.WindowsTpmRuntimeError,
        match="password response auth area is invalid",
    ):
        runtime._require_pw_response(raw)
