from __future__ import annotations

import importlib.metadata as metadata
from pathlib import Path


def test_packaged_post_preflight_materializer_entrypoint_points_at_non_applying_cli():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8")
        assert (
            'continuity-project-update-materialize-ready = "continuityos.project_update_post_preflight_materializer_cli:main"'
            in text
        )
        return

    points = {
        item.name: item.value
        for item in metadata.entry_points(group="console_scripts")
    }
    assert (
        points["continuity-project-update-materialize-ready"]
        == "continuityos.project_update_post_preflight_materializer_cli:main"
    )
