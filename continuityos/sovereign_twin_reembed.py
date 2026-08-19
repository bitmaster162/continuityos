"""Fail-closed re-embedding migration for Sovereign Twin memory.

The source DB is never mutated. A SQLite-consistent snapshot is created first,
then every memory row is copied to a fresh target DB with a newly computed local
embedding while preserving stable item IDs and metadata.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from typing import Any

from .store import Store, pack_vec
from .sovereign_twin_runtime import (
    DEFAULT_EMBEDDING_MODEL,
    LmStudioClient,
    NOMIC_DOCUMENT_TASK,
    NOMIC_QUERY_TASK,
)

REEMBED_RECEIPT_SCHEMA = "sovereign-twin.memory-reembed-receipt/v1"
MEMORY_MANIFEST_SCHEMA = "sovereign-twin.memory-manifest/v1"


class TwinReembedError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _snapshot_database(source: Path, snapshot: Path) -> None:
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    if snapshot.exists():
        raise TwinReembedError(f"snapshot already exists: {snapshot}")
    src_uri = source.resolve().as_uri() + "?mode=ro"
    src = sqlite3.connect(src_uri, uri=True)
    dst = sqlite3.connect(str(snapshot))
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()


def _row_fingerprint(row: sqlite3.Row) -> tuple[Any, ...]:
    return (
        int(row["id"]),
        str(row["namespace"]),
        str(row["text"]),
        str(row["tags"]),
        str(row["meta"]),
        float(row["created_at"]),
        float(row["updated_at"]),
        row["key"],
        int(row["version"]),
    )


def _read_rows(db: Path) -> list[sqlite3.Row]:
    store = Store(str(db), read_only=True)
    try:
        return list(store.con.execute(
            "SELECT id,namespace,text,tags,meta,vec,created_at,updated_at,key,version "
            "FROM items ORDER BY id"
        ).fetchall())
    finally:
        store.con.close()


def _namespace_counts(rows: list[sqlite3.Row]) -> dict[str, int]:
    counts = Counter(str(r["namespace"]) for r in rows)
    return {k: counts[k] for k in sorted(counts)}


def _vector_dimension_counts(rows: list[sqlite3.Row]) -> dict[str, int]:
    counts = Counter(len(r["vec"]) // 4 for r in rows if r["vec"] is not None)
    return {str(k): counts[k] for k in sorted(counts)}


def _write_target(rows: list[sqlite3.Row], target: Path, *, client: LmStudioClient, embedding_model: str) -> int:
    if target.exists():
        raise TwinReembedError(f"target already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    store = Store(str(target))
    embedding_dim: int | None = None
    try:
        with store._lock:
            for row in rows:
                vec = client.embed(
                    str(row["text"]),
                    model=embedding_model,
                    task=NOMIC_DOCUMENT_TASK,
                )
                if embedding_dim is None:
                    embedding_dim = len(vec)
                    if embedding_dim <= 0:
                        raise TwinReembedError("embedding model returned an empty vector")
                elif len(vec) != embedding_dim:
                    raise TwinReembedError(
                        f"embedding dimension changed during migration: {embedding_dim} -> {len(vec)}"
                    )
                store.con.execute(
                    "INSERT INTO items(id,namespace,text,tags,meta,vec,created_at,updated_at,key,version) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        int(row["id"]), str(row["namespace"]), str(row["text"]),
                        str(row["tags"]), str(row["meta"]), pack_vec(vec),
                        float(row["created_at"]), float(row["updated_at"]), row["key"], int(row["version"]),
                    ),
                )
                if store.fts:
                    try:
                        tags = json.loads(row["tags"])
                    except Exception:
                        tags = []
                    store.con.execute(
                        "INSERT INTO items_fts(rowid,text,tags,namespace) VALUES(?,?,?,?)",
                        (int(row["id"]), str(row["text"]), " ".join(str(x) for x in tags), str(row["namespace"])),
                    )
            max_id = max((int(r["id"]) for r in rows), default=0)
            if max_id:
                store.con.execute("DELETE FROM sqlite_sequence WHERE name='items'")
                store.con.execute("INSERT INTO sqlite_sequence(name,seq) VALUES('items',?)", (max_id,))
            store.con.commit()
    except Exception:
        try:
            store.con.close()
        finally:
            try:
                target.unlink()
            except OSError:
                pass
        raise
    else:
        store.con.close()
    if embedding_dim is None:
        probe = client.embed(
            "Sovereign Twin empty-memory embedding probe",
            model=embedding_model,
            task=NOMIC_DOCUMENT_TASK,
        )
        embedding_dim = len(probe)
    return int(embedding_dim)


def _verify_parity(source_rows: list[sqlite3.Row], target: Path, expected_dim: int) -> dict[str, Any]:
    target_rows = _read_rows(target)
    source_fp = [_row_fingerprint(r) for r in source_rows]
    target_fp = [_row_fingerprint(r) for r in target_rows]
    dims = _vector_dimension_counts(target_rows)
    namespace_parity = _namespace_counts(source_rows) == _namespace_counts(target_rows)
    row_parity = source_fp == target_fp
    all_vectors_present = len(target_rows) == sum(dims.values())
    dimension_ok = (not target_rows and not dims) or list(dims.keys()) == [str(expected_dim)]
    ok = (
        len(source_rows) == len(target_rows)
        and namespace_parity
        and row_parity
        and all_vectors_present
        and dimension_ok
    )
    return {
        "ok": ok,
        "source_count": len(source_rows),
        "target_count": len(target_rows),
        "namespace_parity": namespace_parity,
        "stable_row_metadata_parity": row_parity,
        "all_vectors_present": all_vectors_present,
        "target_vector_dimension_counts": dims,
        "expected_embedding_dimension": expected_dim,
    }


def reembed_memory(
    source_db: str,
    target_db: str,
    *,
    client: LmStudioClient,
    embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    commit: bool = False,
) -> dict[str, Any]:
    source = Path(source_db).expanduser().resolve()
    target = Path(target_db).expanduser().resolve()
    if not source.exists():
        raise TwinReembedError(f"source DB missing: {source}")
    if source == target:
        raise TwinReembedError("source and target DB must be different paths")
    rows = _read_rows(source)
    probe = client.embed(
        "Sovereign Twin re-embedding dimension probe",
        model=embedding_model,
        task=NOMIC_QUERY_TASK,
    )
    selected_dim = len(probe)
    if selected_dim <= 0:
        raise TwinReembedError("selected embedding model returned an empty vector")
    embedding_contract = {
        "document_task_prefix": NOMIC_DOCUMENT_TASK,
        "query_task_prefix": NOMIC_QUERY_TASK,
    }
    plan = {
        "ok": True,
        "commit": bool(commit),
        "source_db": str(source),
        "target_db": str(target),
        "source_count": len(rows),
        "source_namespaces": _namespace_counts(rows),
        "source_vector_dimension_counts": _vector_dimension_counts(rows),
        "embedding_model": embedding_model,
        "embedding_dimension": selected_dim,
        "embedding_contract": embedding_contract,
        "execution_authority": "NONE",
        "can_execute": False,
        "source_mutated": False,
    }
    if not commit:
        return {**plan, "dry_run": True}
    if target.exists():
        raise TwinReembedError(f"target already exists: {target}")

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    snapshot = source.with_name(f"{source.stem}.reembed-source-{stamp}{source.suffix}")
    _snapshot_database(source, snapshot)
    snapshot_sha = _sha256(snapshot)
    snapshot_rows = _read_rows(snapshot)
    if [_row_fingerprint(r) for r in rows] != [_row_fingerprint(r) for r in snapshot_rows]:
        raise TwinReembedError("SQLite snapshot parity failed before migration")

    actual_dim = _write_target(snapshot_rows, target, client=client, embedding_model=embedding_model)
    if actual_dim != selected_dim:
        try:
            target.unlink()
        except OSError:
            pass
        raise TwinReembedError(f"embedding dimension changed: probe={selected_dim}, migration={actual_dim}")

    verification = _verify_parity(snapshot_rows, target, selected_dim)
    if not verification["ok"]:
        raise TwinReembedError(f"target parity verification failed: {verification}")

    target_sha = _sha256(target)
    manifest = {
        "schema": MEMORY_MANIFEST_SCHEMA,
        "db": str(target),
        "embedding_model": embedding_model,
        "embedding_dimension": selected_dim,
        "embedding_contract": embedding_contract,
        "source_snapshot": str(snapshot),
        "source_snapshot_sha256": snapshot_sha,
        "updated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_authority": "NONE",
        "can_execute": False,
    }
    manifest_path = target.with_name(target.stem + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    receipt = {
        "schema": REEMBED_RECEIPT_SCHEMA,
        **plan,
        "dry_run": False,
        "source_snapshot": str(snapshot),
        "source_snapshot_sha256": snapshot_sha,
        "target_sha256": target_sha,
        "verification": verification,
        "manifest": str(manifest_path),
        "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    receipt_path = target.with_name(target.stem + ".reembed-receipt.json")
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {**receipt, "receipt": str(receipt_path)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m continuityos.sovereign_twin_reembed")
    p.add_argument("--source", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--base-url", default="http://127.0.0.1:1234")
    p.add_argument("--embedding-model", default=DEFAULT_EMBEDDING_MODEL)
    p.add_argument("--commit", action="store_true")
    args = p.parse_args(argv)
    try:
        result = reembed_memory(
            args.source,
            args.target,
            client=LmStudioClient(args.base_url),
            embedding_model=args.embedding_model,
            commit=args.commit,
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "error": str(exc),
            "error_class": type(exc).__name__,
            "execution_authority": "NONE",
            "can_execute": False,
        }, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
