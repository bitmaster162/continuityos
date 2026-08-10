from __future__ import annotations

import importlib.metadata as metadata


def test_packaged_project_update_preflight_entrypoint_points_at_verified_cli():
    matches = {
        ep.name: ep.value
        for ep in metadata.entry_points(group="console_scripts")
        if ep.name == "continuity-project-update-preflight"
    }
    assert matches == {
        "continuity-project-update-preflight": "continuityos.current_project_update_preflight_cli:main"
    }
