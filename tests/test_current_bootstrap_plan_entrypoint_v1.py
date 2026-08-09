from __future__ import annotations

import importlib.metadata as metadata
from pathlib import Path


def test_packaged_bootstrap_plan_entrypoint_points_at_verified_cli():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8")
        assert 'continuity-memory-bootstrap-plan = "continuityos.current_bootstrap_plan_cli:main"' in text
        return

    points = {
        item.name: item.value
        for item in metadata.entry_points(group="console_scripts")
    }
    assert points["continuity-memory-bootstrap-plan"] == "continuityos.current_bootstrap_plan_cli:main"
