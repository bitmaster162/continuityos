from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bench import locomo_sealed, recall_sealed
from bench.sealing import model_identity, normalize_sha256, require_sealed_model


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_normalize_sha256_rejects_non_sha256():
    with pytest.raises(ValueError, match="64 hexadecimal"):
        normalize_sha256("abc", field="fixture")


def test_non_hashing_seal_requires_model_revision_and_digest():
    identity = model_identity(
        embedder="fastembed",
        model_name="BAAI/bge-small-en-v1.5",
        model_revision=None,
        model_sha256=None,
        package_name="fastembed",
    )
    assert identity["identity_assurance"] == "NAME_ONLY"
    with pytest.raises(ValueError, match="model-revision"):
        require_sealed_model(identity)


def test_recall_sealed_hashing_writes_result_and_manifest(tmp_path: Path):
    result = tmp_path / "recall.json"
    manifest = tmp_path / "recall.manifest.json"
    assert (
        recall_sealed.main(
            [
                "--embedder",
                "hashing",
                "--json-out",
                str(result),
                "--manifest-out",
                str(manifest),
            ]
        )
        == 0
    )
    payload = json.loads(result.read_text(encoding="utf-8"))
    sealed = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["schema"] == "continuityos-recall-sealed-result-v1"
    assert len(payload["dataset"]["sha256"]) == 64
    assert payload["model"]["identity_assurance"] == "TRACKED_CODE_ONLY"
    assert sealed["result"]["sha256"] == _sha256(result)
    assert sealed["repo"]["status"] == "AVAILABLE"
    assert len(sealed["repo"]["head"]) == 40
    assert len(sealed["repo"]["tree"]) == 40
    assert sealed["authority"]["execution_authority"] == "NONE"
    assert sealed["authority"]["can_trade"] is False


def test_locomo_sealed_checksum_and_raw_case_receipt(tmp_path: Path):
    dataset = tmp_path / "locomo.json"
    dataset.write_text(
        json.dumps(
            [
                {
                    "conversation": {
                        "session_1": [
                            {"dia_id": "d1", "speaker": "A", "text": "Alpha likes tea."},
                            {"dia_id": "d2", "speaker": "B", "text": "Beta likes coffee."},
                        ]
                    },
                    "qa": [
                        {
                            "question": "Alpha likes tea",
                            "evidence": ["d1"],
                        }
                    ],
                }
            ],
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    digest = _sha256(dataset)
    result = tmp_path / "locomo.result.json"
    manifest = tmp_path / "locomo.manifest.json"
    assert (
        locomo_sealed.main(
            [
                "--data",
                str(dataset),
                "--expected-sha256",
                digest,
                "--embedder",
                "hashing",
                "--json-out",
                str(result),
                "--manifest-out",
                str(manifest),
            ]
        )
        == 0
    )
    payload = json.loads(result.read_text(encoding="utf-8"))
    sealed = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["dataset"]["sha256_match"] is True
    assert payload["metrics"]["questions"] == 1
    assert payload["cases"][0]["gold_evidence_ids"] == ["d1"]
    assert payload["cases"][0]["first_gold_rank"] == 1
    assert sealed["dataset"]["sha256"] == digest
    assert sealed["result"]["sha256"] == _sha256(result)


def test_locomo_sealed_rejects_dataset_sha_mismatch(tmp_path: Path):
    dataset = tmp_path / "locomo.json"
    dataset.write_text("[]", encoding="utf-8")
    with pytest.raises(SystemExit):
        locomo_sealed.main(
            [
                "--data",
                str(dataset),
                "--expected-sha256",
                "0" * 64,
                "--json-out",
                str(tmp_path / "result.json"),
                "--manifest-out",
                str(tmp_path / "manifest.json"),
            ]
        )
