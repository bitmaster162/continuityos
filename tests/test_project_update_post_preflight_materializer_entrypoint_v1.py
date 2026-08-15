from __future__ import annotations

import importlib.metadata as metadata


def test_packaged_post_preflight_materializer_entrypoint_points_at_non_applying_cli():
    matches = {
        ep.name: ep.value
        for ep in metadata.entry_points(group="console_scripts")
        if ep.name == "continuity-project-update-materialize-ready"
    }
    assert matches == {
        "continuity-project-update-materialize-ready": "continuityos.project_update_post_preflight_materializer_cli:main"
    }
