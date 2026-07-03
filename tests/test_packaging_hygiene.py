"""PR-8 packaging hygiene: package metadata must be single-source at repo root.

A stray continuityos/pyproject.toml once shadowed the root one — not a runtime
bug, but a packaging trust bug (future edits drift between the two copies).
"""
from pathlib import Path


def test_no_nested_pyproject_inside_package():
    assert Path("pyproject.toml").is_file()
    assert not Path("continuityos/pyproject.toml").exists()
