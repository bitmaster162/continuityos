from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_clean_metadata_receipt_imports_checkout_without_site_packages(tmp_path):
    clean_root = tmp_path / "clean-checkout"
    shutil.copytree(ROOT / "tools", clean_root / "tools")
    shutil.copytree(
        ROOT / "continuityos",
        clean_root / "continuityos",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    receipt = tmp_path / "clean-source-metadata.json"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            "-m",
            "tools.ci_review",
            "metadata",
            "--mode",
            "absent",
            "--source-root",
            str(clean_root),
            "--output",
            str(receipt),
        ],
        cwd=clean_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["metadata_present"] is False
    assert Path(payload["package_path"]).resolve().is_relative_to(clean_root)
