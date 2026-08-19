from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from continuityos.store import Store
from continuityos.sovereign_twin_reembed import TwinReembedError, reembed_memory
from continuityos.sovereign_twin_runtime import NOMIC_DOCUMENT_TASK, NOMIC_QUERY_TASK


class FakeClient:
    def __init__(self, dim: int = 5):
        self.dim = dim
        self.calls = []

    def embed(self, text: str, *, model: str, task=None):
        self.calls.append((text, model, task))
        seed = float((sum(ord(c) for c in text) % 17) + 1)
        return [seed / (i + 1) for i in range(self.dim)]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source(path: Path) -> None:
    s = Store(str(path))
    try:
        first = s.add(
            "alpha memory",
            namespace="facts",
            tags=["one"],
            meta={"type": "fact", "x": 1},
            vec=[0.1, 0.2],
            key="alpha",
        )
        second = s.add(
            "beta memory",
            namespace="notes",
            tags=["two"],
            meta={"type": "note", "x": 2},
            vec=[0.1, 0.2, 0.3],
        )
        assert (first, second) == (1, 2)
    finally:
        s.con.close()


def test_reembed_dry_run_never_creates_target(tmp_path):
    source = tmp_path / "memory.db"
    target = tmp_path / "memory-nomic.db"
    _source(source)
    before = _sha(source)
    client = FakeClient(5)

    out = reembed_memory(str(source), str(target), client=client, commit=False)

    assert out["ok"] is True
    assert out["dry_run"] is True
    assert out["source_count"] == 2
    assert out["source_vector_dimension_counts"] == {"2": 1, "3": 1}
    assert out["embedding_dimension"] == 5
    assert out["embedding_contract"] == {
        "document_task_prefix": NOMIC_DOCUMENT_TASK,
        "query_task_prefix": NOMIC_QUERY_TASK,
    }
    assert client.calls[0][2] == NOMIC_QUERY_TASK
    assert out["source_mutated"] is False
    assert not target.exists()
    assert _sha(source) == before


def test_reembed_commit_preserves_stable_rows_and_replaces_vectors(tmp_path):
    source = tmp_path / "memory.db"
    target = tmp_path / "memory-nomic.db"
    _source(source)
    before = _sha(source)
    client = FakeClient(5)

    out = reembed_memory(str(source), str(target), client=client, commit=True)

    assert out["ok"] is True
    assert out["verification"]["ok"] is True
    assert out["verification"]["source_count"] == 2
    assert out["verification"]["target_count"] == 2
    assert out["verification"]["stable_row_metadata_parity"] is True
    assert out["verification"]["namespace_parity"] is True
    assert out["verification"]["all_vectors_present"] is True
    assert out["verification"]["target_vector_dimension_counts"] == {"5": 2}
    assert client.calls[0][2] == NOMIC_QUERY_TASK
    document_calls = [call for call in client.calls if call[2] == NOMIC_DOCUMENT_TASK]
    assert len(document_calls) == 2
    assert _sha(source) == before

    src = Store(str(source), read_only=True)
    dst = Store(str(target), read_only=True)
    try:
        sr = src.con.execute("SELECT * FROM items ORDER BY id").fetchall()
        dr = dst.con.execute("SELECT * FROM items ORDER BY id").fetchall()
        assert [r["id"] for r in sr] == [r["id"] for r in dr] == [1, 2]
        for a, b in zip(sr, dr):
            for field in ("namespace", "text", "tags", "meta", "created_at", "updated_at", "key", "version"):
                assert a[field] == b[field]
            assert len(b["vec"]) // 4 == 5
    finally:
        src.con.close()
        dst.con.close()

    manifest = Path(out["manifest"])
    receipt = Path(out["receipt"])
    assert manifest.exists()
    assert receipt.exists()
    m = json.loads(manifest.read_text(encoding="utf-8"))
    assert m["embedding_dimension"] == 5
    assert m["embedding_model"] == "text-embedding-nomic-embed-text-v1.5"
    assert m["embedding_contract"] == {
        "document_task_prefix": NOMIC_DOCUMENT_TASK,
        "query_task_prefix": NOMIC_QUERY_TASK,
    }
    assert m["execution_authority"] == "NONE"
    assert m["can_execute"] is False


def test_reembed_refuses_same_source_and_target(tmp_path):
    source = tmp_path / "memory.db"
    _source(source)
    with pytest.raises(TwinReembedError, match="different paths"):
        reembed_memory(str(source), str(source), client=FakeClient(), commit=True)


def test_reembed_refuses_existing_target(tmp_path):
    source = tmp_path / "memory.db"
    target = tmp_path / "target.db"
    _source(source)
    target.write_bytes(b"do-not-overwrite")
    before = target.read_bytes()
    with pytest.raises(TwinReembedError, match="target already exists"):
        reembed_memory(str(source), str(target), client=FakeClient(), commit=True)
    assert target.read_bytes() == before
