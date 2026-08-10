from __future__ import annotations

from pathlib import Path


def test_packaged_project_update_preflight_entrypoint_points_at_verified_cli():
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    assert (
        'continuity-project-update-preflight = "continuityos.current_project_update_preflight_cli:main"'
        in text
    )
