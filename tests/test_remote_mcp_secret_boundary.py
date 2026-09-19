import pytest

from continuityos.remote_mcp_server import RemoteSurface


def test_git_metadata_and_common_credential_files_are_denied(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        "[remote \"origin\"]\nurl = https://token@example.invalid/repo.git\n",
        encoding="utf-8",
    )
    (tmp_path / ".netrc").write_text("machine example.invalid login x password y", encoding="utf-8")
    (tmp_path / ".npmrc").write_text("//registry.example.invalid/:_authToken=secret", encoding="utf-8")
    (tmp_path / "safe.txt").write_text("ok", encoding="utf-8")

    surface = RemoteSurface(enabled=True, roots=[tmp_path])
    listing = surface.list_dir(".")
    names = {entry["name"] for entry in listing["entries"]}

    assert ".git" not in names
    assert ".netrc" not in names
    assert ".npmrc" not in names
    assert "safe.txt" in names

    with pytest.raises(PermissionError, match="sensitive directory denied"):
        surface.read_text(".git/config")
    with pytest.raises(PermissionError, match="sensitive file denied"):
        surface.read_text(".netrc")
    with pytest.raises(PermissionError, match="sensitive file denied"):
        surface.read_text(".npmrc")
