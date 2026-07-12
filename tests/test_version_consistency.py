from pathlib import Path
import re

import continuityos
from continuityos._version import __version__ as canonical_version


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
VERSION_MODULE = ROOT / "continuityos" / "_version.py"


def _pyproject_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


def _source_version() -> str:
    match = re.search(
        r'(?m)^__version__\s*=\s*"([^"]+)"',
        VERSION_MODULE.read_text(encoding="utf-8"),
    )
    assert match, "continuityos/_version.py must declare __version__"
    return match.group(1)


def test_package_version_has_one_canonical_source():
    assert continuityos.__version__ == canonical_version == _source_version()
    text = _pyproject_text()
    assert 'dynamic = ["version"]' in text
    assert 'version = {attr = "continuityos._version.__version__"}' in text


def test_canonical_embedding_extras_are_declared():
    text = _pyproject_text()
    for extra in ("fast", "st", "m2v", "embeddings"):
        assert re.search(rf'(?m)^{re.escape(extra)}\s*=', text), f"missing optional extra: {extra}"


def test_dev_extra_includes_ruff():
    text = _pyproject_text()
    match = re.search(r'(?m)^dev\s*=\s*\[(.*?)\]', text)
    assert match, "missing dev optional extra"
    assert "ruff" in match.group(1)
