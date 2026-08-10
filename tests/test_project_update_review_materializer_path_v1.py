from __future__ import annotations

import os
from pathlib import Path

import pytest

import continuityos.project_update_review_materializer as mat


def test_materializer_refuses_symlinked_output_ancestor_before_mkdir(monkeypatch, tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real_parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink unavailable")

    monkeypatch.setattr(mat, "inspect_current_session", lambda: {"mode": mat.MODE_LEGACY})
    # Path safety must fail after packet validation. Isolate the packet side so this
    # regression specifically exercises the R40 canonical-parent invariant.
    monkeypatch.setattr(mat, "_stable_read", lambda *a, **k: b"{}")
    monkeypatch.setattr(
        mat,
        "strict_json_loads",
        lambda payload: {},
    )
    monkeypatch.setattr(
        mat,
        "_validate_packet",
        lambda packet: {
            "packet": {"packet_id": "purp-test", "project_id": "project:test"},
            "proposal_bytes": b"{}",
            "proposal_sha256": "0" * 64,
            "skeleton_bytes": b"{}",
        },
    )

    out = alias / "review"
    result = mat.materialize_project_update_review(tmp_path / "packet.json", out)

    assert result["terminal"] == "PROJECT_UPDATE_MATERIALIZATION_REVISE"
    assert result["reason"] == "MATERIALIZATION_INPUT_INVALID"
    assert not (real_parent / "review").exists()
