"""R15B hardware-free tests for real-provider binding preparation."""
from __future__ import annotations

import ast
import hashlib
import inspect

import pytest

from continuityos.gate import tpm2_provider_binding as binding
from continuityos.gate.monotonic_anchor import BoundMonotonicAnchorProfile


def marshal_nv_public(
    *,
    nv_index: int = 0x01500030,
    name_alg: int = 0x000B,
    attributes: int = 0x00040040,
    auth_policy: bytes = b"",
    data_size: int = 32,
) -> bytes:
    return b"".join((
        nv_index.to_bytes(4, "big"),
        name_alg.to_bytes(2, "big"),
        attributes.to_bytes(4, "big"),
        len(auth_policy).to_bytes(2, "big"),
        auth_policy,
        data_size.to_bytes(2, "big"),
    ))


def raw_name(tpms: bytes) -> bytes:
    return b"\x00\x0b" + hashlib.sha256(tpms).digest()


def constraints(
    *,
    nv_index: int = 0x01500030,
    attributes: int = 0x00040040,
    auth_policy_sha256: str | None = None,
) -> binding.Tpm2NvBindingConstraints:
    return binding.Tpm2NvBindingConstraints(
        nv_index=nv_index,
        tpma_nv_mask=attributes,
        auth_policy_sha256=auth_policy_sha256,
        backend_kind="TEST_FAKE_TPM2",
        transport_identity="test-local-tpm-v1",
    )


def snapshot(
    *,
    c: binding.Tpm2NvBindingConstraints | None = None,
    digest: str = "0" * 64,
    tpms: bytes | None = None,
    **updates,
) -> dict:
    c = c or constraints()
    if tpms is None:
        tpms = marshal_nv_public(
            nv_index=c.nv_index,
            attributes=c.tpma_nv_mask,
        )
    value = {
        "nv_index": c.nv_index,
        "tpma_nv_mask": c.tpma_nv_mask,
        "auth_policy_sha256": c.auth_policy_sha256,
        "backend_kind": c.backend_kind,
        "transport_identity": c.transport_identity,
        "nv_type": "TPM_NT_EXTEND",
        "name_alg": "SHA256",
        "data_size": 32,
        "orderly": False,
        "tpms_nv_public_marshaled": tpms,
        "raw_tpm_name": raw_name(tpms),
        "observed_nv_extend_digest": digest,
    }
    value.update(updates)
    return value


def profile_from_snapshot(
    *, c: binding.Tpm2NvBindingConstraints | None = None, digest: str = "0" * 64
) -> binding.BoundTpm2NvExtendProfile:
    c = c or constraints()
    return binding.derive_profile_candidate(
        raw_snapshot=snapshot(c=c, digest=digest),
        constraints=c,
    )


class FakeBackend:
    def __init__(self, raw: dict):
        self.raw = dict(raw)
        self.read_calls = 0
        self.extend_calls = 0

    def read_snapshot(self, *, profile):
        self.read_calls += 1
        return dict(self.raw)

    def extend_once(
        self,
        *,
        profile,
        expected_previous_digest: str,
        commitment_sha256: str,
    ):
        self.extend_calls += 1
        assert self.raw["observed_nv_extend_digest"] == expected_previous_digest
        self.raw["observed_nv_extend_digest"] = hashlib.sha256(
            bytes.fromhex(expected_previous_digest)
            + bytes.fromhex(commitment_sha256)
        ).hexdigest()
        return dict(self.raw)


def test_profile_candidate_pins_wire_identity_and_controller_fingerprint() -> None:
    c = constraints()
    raw = snapshot(c=c, digest="1" * 64)
    profile = binding.derive_profile_candidate(raw_snapshot=raw, constraints=c)
    tpms = raw["tpms_nv_public_marshaled"]
    name = raw["raw_tpm_name"]
    assert profile.nv_public_sha256 == hashlib.sha256(tpms).hexdigest()
    assert profile.nv_name_sha256 == hashlib.sha256(name).hexdigest()
    assert profile.genesis_digest == "1" * 64
    assert profile.binding_document()["schema"] == binding.BINDING_SCHEMA
    assert profile.binding_document()["provider"] == binding.PROVIDER_NAME
    assert len(profile.binding_sha256()) == 64
    anchor = profile.anchor_profile()
    assert isinstance(anchor, BoundMonotonicAnchorProfile)
    assert anchor.nv_public_sha256 == profile.nv_public_sha256
    assert anchor.nv_name_sha256 == profile.nv_name_sha256
    assert anchor.genesis_digest == profile.genesis_digest


@pytest.mark.parametrize(
    "kwargs",
    [
        {"nv_index": 0x00FFFFFF},
        {"attributes": 0x00040000},
        {"attributes": 0x04040040},
    ],
)
def test_constraints_reject_invalid_handle_type_or_orderly(kwargs) -> None:
    with pytest.raises(binding.Tpm2ProviderBindingError):
        constraints(**kwargs)


def test_constraints_require_explicit_backend_and_transport() -> None:
    with pytest.raises(binding.Tpm2ProviderBindingError, match="backend kind"):
        binding.Tpm2NvBindingConstraints(
            nv_index=0x01500030,
            tpma_nv_mask=0x00040040,
            auth_policy_sha256=None,
            backend_kind="",
            transport_identity="local",
        )
    with pytest.raises(binding.Tpm2ProviderBindingError, match="transport identity"):
        binding.Tpm2NvBindingConstraints(
            nv_index=0x01500030,
            tpma_nv_mask=0x00040040,
            auth_policy_sha256=None,
            backend_kind="WINDOWS_TBS",
            transport_identity="",
        )


def test_candidate_rejects_outer_tpm2b_prefix_and_wrong_name() -> None:
    c = constraints()
    inner = marshal_nv_public(nv_index=c.nv_index, attributes=c.tpma_nv_mask)
    outer = len(inner).to_bytes(2, "big") + inner
    with pytest.raises(binding.Tpm2ProviderBindingError):
        binding.derive_profile_candidate(raw_snapshot=snapshot(c=c, tpms=outer), constraints=c)
    wrong_name = snapshot(c=c, tpms=inner)
    wrong_name["raw_tpm_name"] = b"\x00\x0b" + b"x" * 32
    with pytest.raises(binding.Tpm2ProviderBindingError, match="Name"):
        binding.derive_profile_candidate(raw_snapshot=wrong_name, constraints=c)


@pytest.mark.parametrize(
    "wire_kwargs",
    [
        {"name_alg": 0x000C},
        {"attributes": 0x00040000},
        {"attributes": 0x04040040},
        {"data_size": 64},
        {"nv_index": 0x01500031},
    ],
)
def test_candidate_rejects_wire_profile_drift(wire_kwargs) -> None:
    c = constraints()
    kwargs = {"nv_index": c.nv_index, "attributes": c.tpma_nv_mask}
    kwargs.update(wire_kwargs)
    tpms = marshal_nv_public(**kwargs)
    raw = snapshot(c=c, tpms=tpms)
    with pytest.raises(binding.Tpm2ProviderBindingError):
        binding.derive_profile_candidate(raw_snapshot=raw, constraints=c)


def test_auth_policy_is_bound_to_exact_public_area_bytes() -> None:
    policy = bytes(range(32))
    c = constraints(auth_policy_sha256=policy.hex())
    tpms = marshal_nv_public(
        nv_index=c.nv_index,
        attributes=c.tpma_nv_mask,
        auth_policy=policy,
    )
    raw = snapshot(c=c, tpms=tpms)
    profile = binding.derive_profile_candidate(raw_snapshot=raw, constraints=c)
    assert profile.constraints.auth_policy_sha256 == policy.hex()
    wrong = marshal_nv_public(
        nv_index=c.nv_index,
        attributes=c.tpma_nv_mask,
        auth_policy=bytes(reversed(policy)),
    )
    with pytest.raises(binding.Tpm2ProviderBindingError, match="authPolicy"):
        binding.derive_profile_candidate(raw_snapshot=snapshot(c=c, tpms=wrong), constraints=c)


def test_bound_provider_read_and_compare_extend_happy_path() -> None:
    raw = snapshot(digest="0" * 64)
    profile = binding.derive_profile_candidate(
        raw_snapshot=raw, constraints=constraints()
    )
    backend = FakeBackend(raw)
    provider = binding.BoundTpm2NvExtendProvider(backend, profile=profile)
    assert provider.read_snapshot()["observed_digest"] == "0" * 64
    commitment = "a" * 64
    expected = hashlib.sha256(bytes(32) + bytes.fromhex(commitment)).hexdigest()
    result = provider.extend(
        expected_previous_digest="0" * 64,
        commitment_sha256=commitment,
    )
    assert result["observed_digest"] == expected
    assert result["nv_public_sha256"] == profile.nv_public_sha256
    assert result["nv_name_sha256"] == profile.nv_name_sha256
    assert backend.extend_calls == 1


def test_bound_provider_blocks_stale_frontier_before_backend_write() -> None:
    raw = snapshot(digest="0" * 64)
    profile = binding.derive_profile_candidate(
        raw_snapshot=raw, constraints=constraints()
    )
    backend = FakeBackend(raw)
    backend.raw["observed_nv_extend_digest"] = "1" * 64
    provider = binding.BoundTpm2NvExtendProvider(backend, profile=profile)
    with pytest.raises(binding.Tpm2ProviderBindingError, match="frontier moved"):
        provider.extend(
            expected_previous_digest="0" * 64,
            commitment_sha256="a" * 64,
        )
    assert backend.extend_calls == 0


def test_bound_provider_rejects_controller_identity_substitution() -> None:
    raw = snapshot(digest="0" * 64)
    candidate = binding.derive_profile_candidate(
        raw_snapshot=raw, constraints=constraints()
    )
    wrong = binding.BoundTpm2NvExtendProfile(
        constraints=candidate.constraints,
        nv_public_sha256="f" * 64,
        nv_name_sha256=candidate.nv_name_sha256,
        genesis_digest=candidate.genesis_digest,
    )
    provider = binding.BoundTpm2NvExtendProvider(FakeBackend(raw), profile=wrong)
    with pytest.raises(binding.Tpm2ProviderBindingError, match="identity"):
        provider.read_snapshot()


class MovingAfterExtendBackend(FakeBackend):
    def extend_once(self, **kwargs):
        returned = super().extend_once(**kwargs)
        self.raw["observed_nv_extend_digest"] = "f" * 64
        return returned


def test_bound_provider_detects_post_extend_movement() -> None:
    raw = snapshot(digest="0" * 64)
    profile = binding.derive_profile_candidate(
        raw_snapshot=raw, constraints=constraints()
    )
    provider = binding.BoundTpm2NvExtendProvider(
        MovingAfterExtendBackend(raw), profile=profile
    )
    with pytest.raises(binding.Tpm2ProviderBindingError, match="changed after extend"):
        provider.extend(
            expected_previous_digest="0" * 64,
            commitment_sha256="a" * 64,
        )


def test_unprovisioned_backend_fails_closed() -> None:
    raw = snapshot(digest="0" * 64)
    profile = binding.derive_profile_candidate(
        raw_snapshot=raw, constraints=constraints()
    )
    provider = binding.BoundTpm2NvExtendProvider(
        binding.UnprovisionedTpm2NvBackend(), profile=profile
    )
    with pytest.raises(binding.Tpm2ProviderBindingError, match="unprovisioned"):
        provider.read_snapshot()


def test_r15b_binding_module_has_no_hardware_or_effectful_imports() -> None:
    source = inspect.getsource(binding)
    tree = ast.parse(source)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    forbidden = {
        "os", "subprocess", "ctypes", "socket", "requests", "urllib",
        "tpm2_pytss", "win32api", "win32com",
    }
    assert roots.isdisjoint(forbidden)
    assert "acceptance_origin_custody" not in source


def test_r15b_binding_module_does_not_expose_admin_surface() -> None:
    public_names = {name for name in dir(binding) if not name.startswith("_")}
    forbidden = {"provision", "reset", "clear", "undefine", "define", "take_ownership"}
    assert public_names.isdisjoint(forbidden)
