from pathlib import Path
import re

import continuityos


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"


def _pyproject_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


def _pyproject_version() -> str:
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', _pyproject_text())
    assert match, "pyproject.toml must declare [project].version"
    return match.group(1)


def test_package_version_matches_pyproject():
    assert continuityos.__version__ == _pyproject_version()


def test_canonical_embedding_extras_are_declared():
    text = _pyproject_text()
    for extra in ("fast", "st", "m2v", "embeddings"):
        assert re.search(rf'(?m)^{re.escape(extra)}\s*=', text), f"missing optional extra: {extra}"


def test_dev_extra_includes_ruff():
    text = _pyproject_text()
    match = re.search(r'(?m)^dev\s*=\s*\[(.*?)\]', text)
    assert match, "missing dev optional extra"
    assert "ruff" in match.group(1)
