from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
LICENSE_FILE = ROOT / "LICENSE"
PYPROJECT_FILE = ROOT / "pyproject.toml"


CANONICAL_APACHE_2_CLAUSES = (
    "excluding those notices that do not pertain to any part of\n"
    "          the Derivative Works; and",
    "wherever such third-party notices normally appear. The contents\n"
    "          of the NOTICE file are for informational purposes only",
    "You may add Your own copyright statement to Your modifications and",
    "Notwithstanding the above, nothing herein shall supersede or modify",
    "the terms of any separate license agreement you may have executed\n"
    "      with Licensor regarding such Contributions.",
)


def test_apache_2_license_text_is_not_truncated():
    text = LICENSE_FILE.read_text(encoding="utf-8")

    assert text.startswith("                                 Apache License\n")
    assert "Version 2.0, January 2004" in text
    assert text.count("END OF TERMS AND CONDITIONS") == 1

    for clause in CANONICAL_APACHE_2_CLAUSES:
        assert clause in text, f"missing canonical Apache-2.0 clause: {clause!r}"

    assert "Copyright [yyyy] [name of copyright owner]" in text
    assert "Copyright 2026 ContinuityOS contributors" not in text


def test_project_metadata_declares_apache_2_spdx_identity():
    text = PYPROJECT_FILE.read_text(encoding="utf-8")
    assert re.search(r'(?m)^license\s*=\s*"Apache-2\.0"\s*$', text)
