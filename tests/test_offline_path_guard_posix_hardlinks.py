"""POSIX hard-link rejection for R6.1 offline, read-only evidence."""
import hashlib
import json
import os

import pytest

from continuityos import _offline_path_guard as guard
from continuityos.central_memory_mcp_adapter import (
    CentralMemoryMCPAdapter,
    POLICY_SCHEMA,
    RECEIPT_SCHEMA,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="POSIX st_nlink boundary (Windows has handle link checks)"
)


def test_posix_single_link_still_reads(tmp_path):
    source = tmp_path / "policy.json"
    source.write_bytes(b'{"fixture":"plain"}')
    assert source.stat().st_nlink == 1
    assert guard.read_bounded_file(source, 128) == b'{"fixture":"plain"}'


@pytest.mark.parametrize("filename", ("AGENT_POLICY_R61.json", "R61_LOCAL_REVIEW_RECEIPT.json"))
def test_posix_existing_hardlink_is_rejected(tmp_path, filename):
    source = tmp_path / filename
    source.write_bytes(b'{"fixture":"link"}')
    alias = tmp_path / "external_alias.json"
    os.link(source, alias)
    assert source.stat().st_nlink == 2
    with pytest.raises(ValueError, match="OFFLINE_PATH_UNSAFE"):
        guard.read_bounded_file(source, 128)
    assert alias.read_bytes() == b'{"fixture":"link"}'


@pytest.mark.parametrize("when", ("after_initial_snapshot", "before_final_snapshot"))
def test_posix_hardlink_added_during_read_is_rejected(tmp_path, monkeypatch, when):
    source = tmp_path / "policy.json"
    source.write_bytes(b'{"fixture":"race"}')
    alias = tmp_path / "external_alias.json"
    original_snapshot = guard._snapshot
    calls = 0

    def adversarial_snapshot(path):
        nonlocal calls
        calls += 1
        if when == "before_final_snapshot" and calls == 2:
            os.link(source, alias)
        result = original_snapshot(path)
        if when == "after_initial_snapshot" and calls == 1:
            os.link(source, alias)
        return result

    monkeypatch.setattr(guard, "_snapshot", adversarial_snapshot)
    with pytest.raises(ValueError, match="OFFLINE_PATH_UNSAFE"):
        guard.read_bounded_file(source, 128)
    assert calls == (1 if when == "after_initial_snapshot" else 2)
    assert alias.exists()
    assert source.stat().st_nlink == 2


@pytest.mark.parametrize("filename", ("AGENT_POLICY_R61.json", "R61_LOCAL_REVIEW_RECEIPT.json"))
def test_posix_adapter_fails_closed_for_linked_evidence(tmp_path, filename):
    root = tmp_path / "agent_view"
    root.mkdir()
    sources = {key: {"sha256": key + "-digest"} for key in ("rozi", "shaytan", "sharmanka")}
    policy = {
        "schema": POLICY_SCHEMA,
        "release_status": "OFFLINE_DRAFT_NOT_DEPLOYED",
        "agent_access": "DENY",
        "effect_authority": "NONE",
        "clients_connected": False,
        "source_binding": sources,
        "policies": [{"id": str(i)} for i in range(10)],
    }
    raw_policy = json.dumps(policy, sort_keys=True).encode("utf-8")
    (root / "AGENT_POLICY_R61.json").write_bytes(raw_policy)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "projection_sha256": hashlib.sha256(raw_policy).hexdigest(),
        "client_connected": False,
        "owner_sqlite_changed": False,
        "sources": sources,
    }
    (root / "R61_LOCAL_REVIEW_RECEIPT.json").write_text(
        json.dumps(receipt), encoding="utf-8"
    )
    linked = root / filename
    os.link(linked, tmp_path / "external_alias.json")
    with pytest.raises(ValueError, match="AGENT_VIEW_FILE_MISSING_OR_LINKED"):
        CentralMemoryMCPAdapter(str(root)).call("agent_view_status", {})
