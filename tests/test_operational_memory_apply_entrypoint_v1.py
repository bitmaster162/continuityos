from __future__ import annotations

from importlib import metadata
from pathlib import Path
import tomllib


def test_packaged_memory_apply_entrypoint_points_at_atomic_gate():
    root = Path(__file__).resolve().parents[1]
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        assert data["project"]["scripts"]["continuity-memory-apply"] == "continuityos.operational_memory_apply_cli:main"
        return

    dist = metadata.distribution("continuityos")
    matches = [
        ep for ep in dist.entry_points
        if ep.group == "console_scripts" and ep.name == "continuity-memory-apply"
    ]
    assert len(matches) == 1
    assert matches[0].value == "continuityos.operational_memory_apply_cli:main"
