from __future__ import annotations

from importlib import metadata
from pathlib import Path
import tomllib


def test_packaged_continuity_work_entrypoint_points_at_verified_cli():
    root = Path(__file__).resolve().parents[1]
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        assert data["project"]["scripts"]["continuity-work"] == "continuityos.current_work_cli:main"
        return

    # Wheel-only CI intentionally runs tests outside the source checkout. Validate
    # the metadata of the actually installed distribution instead of assuming the
    # source pyproject is present.
    dist = metadata.distribution("continuityos")
    matches = [
        ep
        for ep in dist.entry_points
        if ep.group == "console_scripts" and ep.name == "continuity-work"
    ]
    assert len(matches) == 1
    assert matches[0].value == "continuityos.current_work_cli:main"
