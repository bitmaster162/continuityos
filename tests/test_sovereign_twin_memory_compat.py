from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from continuityos.store import Store
from continuityos.sovereign_twin_memory_compat import memory_compatibility_report
from continuityos.sovereign_twin_runtime import NOMIC_DOCUMENT_TASK, NOMIC_QUERY_TASK


class FakeClient:
    def __init__(self, dim: int):
        self.dim = dim
        self.calls = []

    def embed(self, text: str, *, model: str, task=None):
        self.calls.append((text, model, task))
        return [0.1] * self.dim


def test_memory_compat_reports_reembed_required_without_mutation():
    with TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "memory.db")
        store = Store(db)
        try:
            store.add("old vector", vec=[0.1, 0.2])
        finally:
            store.con.close()

        client = FakeClient(3)
        report = memory_compatibility_report(db, client=client, embedding_model="nomic-test")
        assert report["ok"] is False
        assert report["verdict"] == "REEMBED_REQUIRED_DIMENSION_MISMATCH"
        assert report["vector_dimension_counts"] == {"2": 1}
        assert report["selected_embedding_dimension"] == 3
        assert client.calls[0][2] == NOMIC_QUERY_TASK
        assert report["canonical_memory_mutated"] is False
        assert report["execution_authority"] == "NONE"

        verify = Store(db, read_only=True)
        try:
            assert verify.count() == 1
            assert len(verify.get(1)["vec"]) // 4 == 2
        finally:
            verify.con.close()


def test_memory_compat_no_vectors_is_ready():
    with TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "memory.db")
        store = Store(db)
        try:
            store.add("text only")
        finally:
            store.con.close()

        report = memory_compatibility_report(db, client=FakeClient(3), embedding_model="nomic-test")
        assert report["ok"] is True
        assert report["verdict"] == "READY_NO_STORED_VECTORS"
        assert report["vector_count"] == 0
        assert report["vectorless_count"] == 1


def test_dimension_match_without_manifest_is_not_treated_as_semantic_proof():
    with TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "memory.db")
        store = Store(db)
        try:
            store.add("unknown embedder", vec=[0.1, 0.2, 0.3])
        finally:
            store.con.close()

        report = memory_compatibility_report(db, client=FakeClient(3), embedding_model="nomic-test")
        assert report["ok"] is False
        assert report["verdict"] == "DIMENSION_MATCH_UNBOUND_SEMANTICS"
        assert "MATCHING_DIMENSION_DOES_NOT_PROVE_SAME_EMBEDDING_CONTRACT" in report["warnings"]


def test_exact_target_sidecar_manifest_binds_model_dimension_and_tasks():
    with TemporaryDirectory() as tmp:
        db = Path(tmp) / "memory-nomic.db"
        store = Store(str(db))
        try:
            store.add("known nomic vector", vec=[0.1, 0.2, 0.3])
        finally:
            store.con.close()
        sidecar = db.with_name(db.stem + ".manifest.json")
        sidecar.write_text(json.dumps({
            "schema": "sovereign-twin.memory-manifest/v1",
            "db": str(db.resolve()),
            "embedding_model": "nomic-test",
            "embedding_dimension": 3,
            "embedding_contract": {
                "document_task_prefix": NOMIC_DOCUMENT_TASK,
                "query_task_prefix": NOMIC_QUERY_TASK,
            },
        }), encoding="utf-8")

        report = memory_compatibility_report(str(db), client=FakeClient(3), embedding_model="nomic-test")
        assert report["ok"] is True
        assert report["verdict"] == "COMPATIBLE_MANIFEST_BOUND"
        assert report["manifest_bound"] is True
        assert report["manifest_path"] == str(sidecar)
