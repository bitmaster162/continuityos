"""R15B Windows TBS read-only TPM discovery tests."""
from __future__ import annotations

import hashlib
import inspect
import struct

import pytest

from continuityos.gate import windows_tpm_readonly as tbs


def _marshal_public(
    *,
    nv_index: int = 0x01500020,
    name_alg: int = tbs.TPM_ALG_SHA256,
    attributes: int = 0x00040040,
    auth_policy: bytes = b"",
    data_size: int = 32,
) -> bytes:
    return (
        nv_index.to_bytes(4, "big")
        + name_alg.to_bytes(2, "big")
        + attributes.to_bytes(4, "big")
        + len(auth_policy).to_bytes(2, "big")
        + auth_policy
        + data_size.to_bytes(2, "big")
    )
def _name(public: bytes) -> bytes:
    return b"\x00\x0b" + hashlib.sha256(public).digest()


def _read_public_payload(
    *, public: bytes | None = None, raw_name: bytes | None = None
) -> bytes:
    public = public or _marshal_public()
    raw_name = _name(public) if raw_name is None else raw_name
    return (
        len(public).to_bytes(2, "big")
        + public
        + len(raw_name).to_bytes(2, "big")
        + raw_name
    )


def test_get_capability_handle_parser_accepts_ordered_nv_handles() -> None:
    payload = (
        b"\x00"
        + tbs.TPM_CAP_HANDLES.to_bytes(4, "big")
        + (3).to_bytes(4, "big")
        + struct.pack(">III", 0x01410001, 0x01500020, 0x01880011)
    )
    more, handles = tbs._parse_get_capability_handles(payload)
    assert more is False
    assert handles == [0x01410001, 0x01500020, 0x01880011]
@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x02" + tbs.TPM_CAP_HANDLES.to_bytes(4, "big") + (0).to_bytes(4, "big"),
        b"\x00" + (2).to_bytes(4, "big") + (0).to_bytes(4, "big"),
        b"\x00" + tbs.TPM_CAP_HANDLES.to_bytes(4, "big") + (1).to_bytes(4, "big") + (0x81000000).to_bytes(4, "big"),
        b"\x00" + tbs.TPM_CAP_HANDLES.to_bytes(4, "big") + (2).to_bytes(4, "big") + struct.pack(">II", 0x01500020, 0x01500020),
    ],
)
def test_get_capability_handle_parser_rejects_invalid_lists(payload: bytes) -> None:
    with pytest.raises(tbs.WindowsTpmReadOnlyError):
        tbs._parse_get_capability_handles(payload)


def test_nv_read_public_parser_verifies_name_and_metadata() -> None:
    public = _marshal_public(auth_policy=bytes(range(32)))
    result = tbs._parse_nv_read_public(
        _read_public_payload(public=public), expected_handle=0x01500020
    )
    assert result["nv_index"] == 0x01500020
    assert result["nv_type"] == "TPM_NT_EXTEND"
    assert result["data_size"] == 32
    assert result["name_verified"] is True
    assert result["nv_public_sha256"] == hashlib.sha256(public).hexdigest()
def test_nv_read_public_parser_rejects_name_substitution() -> None:
    public = _marshal_public()
    wrong_name = b"\x00\x0b" + b"x" * 32
    with pytest.raises(tbs.WindowsTpmReadOnlyError, match="Name"):
        tbs._parse_nv_read_public(
            _read_public_payload(public=public, raw_name=wrong_name),
            expected_handle=0x01500020,
        )


def test_nv_read_public_parser_rejects_handle_substitution_and_trailing_bytes() -> None:
    public = _marshal_public(nv_index=0x01500021)
    with pytest.raises(tbs.WindowsTpmReadOnlyError, match="another NV index"):
        tbs._parse_nv_read_public(
            _read_public_payload(public=public), expected_handle=0x01500020
        )
    public = _marshal_public()
    with pytest.raises(tbs.WindowsTpmReadOnlyError, match="trailing"):
        tbs._parse_nv_read_public(
            _read_public_payload(public=public) + b"x", expected_handle=0x01500020
        )


def test_public_discovery_record_is_json_safe_and_retains_wire_evidence() -> None:
    value = tbs._parse_nv_read_public(
        _read_public_payload(), expected_handle=0x01500020
    )
    record = tbs.public_discovery_record(value)
    assert record["nv_index_hex"] == "0x01500020"
    assert record["tpms_nv_public_hex"] == value["tpms_nv_public_marshaled"].hex()
    assert record["raw_tpm_name_hex"] == value["raw_tpm_name"].hex()
def test_submit_rejects_non_allowlisted_command_before_loading_tbs() -> None:
    with pytest.raises(tbs.WindowsTpmReadOnlyError, match="allowlist"):
        tbs._submit_readonly(0x00000137, b"")  # TPM2_NV_Write
    with pytest.raises(tbs.WindowsTpmReadOnlyError, match="allowlist"):
        tbs._submit_readonly(0x00000136, b"")  # TPM2_NV_Extend


def test_source_exposes_no_nv_data_read_auth_or_mutation_surface() -> None:
    source = inspect.getsource(tbs)
    forbidden = (
        "NV_Read(", "NV_Write", "NV_Extend", "NV_DefineSpace",
        "NV_UndefineSpace", "ClearControl", "HierarchyControl",
        "password_session", "auth_session", "extend_once",
    )
    assert all(item not in source for item in forbidden)
    assert "TPM_CC_GET_CAPABILITY" in source
    assert "TPM_CC_NV_READ_PUBLIC" in source
    public_functions = {
        name for name, value in vars(tbs).items()
        if inspect.isfunction(value) and not name.startswith("_")
    }
    assert public_functions == {
        "enumerate_nv_handles", "read_nv_public", "discover_nv_public",
        "public_discovery_record",
    }


def test_read_nv_public_rejects_non_nv_handle_before_tbs_access() -> None:
    with pytest.raises(tbs.WindowsTpmReadOnlyError, match="outside"):
        tbs.read_nv_public(0x81000000)
def test_discovery_auth_policy_matches_binding_contract_digest_hex() -> None:
    policy = bytes(range(32))
    public = _marshal_public(auth_policy=policy)
    result = tbs._parse_nv_read_public(
        _read_public_payload(public=public), expected_handle=0x01500020
    )
    assert result["auth_policy_hex"] == policy.hex()
    assert result["auth_policy_sha256"] == policy.hex()


def test_submit_rejects_wrong_parameter_length_before_loading_tbs() -> None:
    with pytest.raises(tbs.WindowsTpmReadOnlyError, match="parameter length"):
        tbs._submit_readonly(tbs.TPM_CC_NV_READ_PUBLIC, b"")
    with pytest.raises(tbs.WindowsTpmReadOnlyError, match="parameter length"):
        tbs._submit_readonly(tbs.TPM_CC_GET_CAPABILITY, b"\x00" * 4)
