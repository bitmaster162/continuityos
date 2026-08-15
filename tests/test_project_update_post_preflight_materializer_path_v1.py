from __future__ import annotations

import hashlib

import pytest

import continuityos.project_update_post_preflight_materializer as mat


def test_materializer_refuses_symlinked_output_parent_before_mkdir(monkeypatch, tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real_parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink unavailable")

    reads = iter([b'{"packet":true}', b'{"authorization":true}', b'{"preflight":true}'])
    monkeypatch.setattr(mat, "inspect_current_session", lambda: {"mode": mat.MODE_LEGACY})
    monkeypatch.setattr(mat, "_stable_read", lambda *a, **k: next(reads))
    monkeypatch.setattr(mat, "_load_object", lambda payload, label: {"payload": label})
    monkeypatch.setattr(
        mat,
        "_validate_packet",
        lambda packet: (
            {"packet_id": "purp-test", "project_id": "project:test"},
            {"proposal_id": "proposal-test"},
            b"{}",
            hashlib.sha256(b"{}").hexdigest(),
        ),
    )
    monkeypatch.setattr(
        mat.apply,
        "_validate_authorization",
        lambda authorization, **kwargs: {
            "authority_class": "DETERMINISTIC_CONTROLLER",
            "authority_id": "test",
            "authority_ref": "test://authority",
        },
    )
    monkeypatch.setattr(mat, "_validate_preflight", lambda *a, **k: None)

    out = alias / "review"
    result = mat.materialize_project_update_after_preflight(
        tmp_path / "packet.json",
        tmp_path / "authorization.json",
        tmp_path / "preflight.json",
        out,
    )

    assert result["terminal"] == "PROJECT_UPDATE_POST_PREFLIGHT_MATERIALIZATION_REVISE"
    assert result["reason"] == "MATERIALIZATION_INPUT_INVALID"
    assert not (real_parent / "review").exists()
