from __future__ import annotations

import importlib.metadata as metadata


def test_packaged_project_update_materializer_entrypoint_points_at_non_authorizing_cli():
    matches = {
        ep.name: ep.value
        for ep in metadata.entry_points(group="console_scripts")
        if ep.name == "continuity-project-update-materialize"
    }
    assert matches == {
        "continuity-project-update-materialize": "continuityos.project_update_review_materializer_cli:main"
    }
