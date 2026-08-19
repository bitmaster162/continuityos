"""Sovereign Twin memory ingestion with local LM Studio embeddings.

Canonical memory writes happen only on explicit user-requested seed/history commit.
Model-generated candidate memories remain in the separate shadow admission queue.
"""
from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any, Iterable, Mapping

from .adapters import import_path
from .memory import Memory
from .store import Store
from .sovereign_twin_runtime import DEFAULT_EMBEDDING_MODEL, LmStudioClient

MEMORY_SEED_SCHEMA = "sovereign-twin.memory-seed/v1"
MEMORY_MANIFEST_SCHEMA = "sovereign-twin.memory-manifest/v1"


class TwinMemoryError(ValueError):
    pass


def _close_memory(memory: Memory) -> None:
    close = getattr(memory.store, "close", None)
    if callable(close):
        close()
    else:
        memory.store.con.close()


def _vector_dimensions_from_store(store: Store) -> list[int]:
    dims = sorted({len(row["vec"]) // 4 for row in store.all_with_vecs() if row["vec"] is not None})
    return dims


def memory_report(db_path: str) -> dict[str, Any]:
    db = Path(db_path).expanduser()
    if not db.exists():
        return {
            "ok": False,
            "db": str(db),
            "error": "MEMORY_DB_MISSING",
            "execution_authority": "NONE",
            "can_execute": False,
        }
    store = Store(str(db), read_only=True)
    try:
        return {
            "ok": True,
            "db": str(db),
            "count": store.count(),
            "namespaces": store.namespaces(),
            "vector_dimensions": _vector_dimensions_from_store(store),
            "execution_authority": "NONE",
            "can_execute": False,
        }
    finally:
        store.con.close()


def _manifest_path(db: Path) -> Path:
    return db.parent / "twin-memory-manifest.json"


def _write_manifest(db: Path, *, embedding_model: str, embedding_dimension: int) -> dict[str, Any]:
    manifest = {
        "schema": MEMORY_MANIFEST_SCHEMA,
        "db": str(db),
        "embedding_model": str(embedding_model),
        "embedding_dimension": int(embedding_dimension),
        "updated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_authority": "NONE",
        "can_execute": False,
    }
    path = _manifest_path(db)
    path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {"path": str(path), **manifest}


def _verify_embedding_compatibility(
    db: Path,
    *,
    client: LmStudioClient,
    embedding_model: str,
) -> tuple[int, list[int]]:
    probe = client.embed("Sovereign Twin embedding compatibility probe", model=embedding_model)
    dim = len(probe)
    if dim <= 0:
        raise TwinMemoryError("embedding probe returned an empty vector")
    store = Store(str(db), read_only=True)
    try:
        existing = _vector_dimensions_from_store(store)
    finally:
        store.con.close()
    if len(existing) > 1:
        raise TwinMemoryError(f"memory DB contains mixed vector dimensions: {existing}")
    if existing and existing[0] != dim:
        raise TwinMemoryError(
            f"embedding dimension mismatch: DB={existing[0]} selected_model={dim}; "
            "use a clean/re-embedded Twin memory DB"
        )
    return dim, existing


def ingest_history(
    db_path: str,
    source_path: str,
    *,
    client: LmStudioClient,
    embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    namespace: str = "imported",
    source: str = "auto",
    roles: Iterable[str] = ("user", "human", "memory"),
    extract_mode: bool = False,
    commit: bool = False,
) -> dict[str, Any]:
    db = Path(db_path).expanduser()
    if not db.exists():
        raise TwinMemoryError("memory DB does not exist; run sovereign-twin init first")
    if not Path(source_path).expanduser().exists():
        raise TwinMemoryError(f"source path does not exist: {source_path}")

    dim = None
    existing_dims: list[int] = []
    if commit:
        dim, existing_dims = _verify_embedding_compatibility(
            db,
            client=client,
            embedding_model=embedding_model,
        )

    memory = Memory(
        str(db),
        embedder=lambda text: client.embed(text, model=embedding_model),
    )
    try:
        result = import_path(
            str(Path(source_path).expanduser()),
            memory,
            namespace=namespace,
            source=source,
            roles=tuple(roles),
            extract_mode=extract_mode,
            dry_run=not commit,
        )
        payload = result.as_dict()
    finally:
        _close_memory(memory)

    manifest = None
    if commit and dim is not None:
        manifest = _write_manifest(db, embedding_model=embedding_model, embedding_dimension=dim)

    return {
        "ok": True,
        "commit": bool(commit),
        "dry_run": not commit,
        "source_path": str(Path(source_path).expanduser()),
        "embedding_model": embedding_model,
        "embedding_dimension": dim,
        "existing_vector_dimensions_before": existing_dims,
        "import": payload,
        "memory": memory_report(str(db)),
        "manifest": manifest,
        "execution_authority": "NONE",
        "can_execute": False,
    }


def _clean_seed_entry(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TwinMemoryError(f"seed entry {index} must be an object")
    text = str(value.get("text", "")).strip()
    namespace = str(value.get("namespace", "notes")).strip()
    if not text or not namespace:
        raise TwinMemoryError(f"seed entry {index} requires non-empty text and namespace")
    tags = value.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(x, str) and x.strip() for x in tags):
        raise TwinMemoryError(f"seed entry {index} tags must be non-empty strings")
    key = value.get("key")
    if key is not None:
        key = str(key).strip()
        if not key:
            raise TwinMemoryError(f"seed entry {index} key cannot be blank")
    mtype = value.get("type")
    if mtype is not None:
        mtype = str(mtype).strip() or None
    return {
        "text": text,
        "namespace": namespace,
        "tags": [x.strip() for x in tags],
        "key": key,
        "type": mtype,
    }


def import_seed(
    db_path: str,
    seed_path: str,
    *,
    client: LmStudioClient,
    embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    commit: bool = False,
) -> dict[str, Any]:
    db = Path(db_path).expanduser()
    if not db.exists():
        raise TwinMemoryError("memory DB does not exist; run sovereign-twin init first")
    path = Path(seed_path).expanduser()
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or raw.get("schema") != MEMORY_SEED_SCHEMA:
        raise TwinMemoryError(f"seed schema must be {MEMORY_SEED_SCHEMA}")
    entries_raw = raw.get("entries")
    if not isinstance(entries_raw, list) or not entries_raw:
        raise TwinMemoryError("seed entries must be a non-empty list")
    entries = [_clean_seed_entry(value, idx) for idx, value in enumerate(entries_raw, 1)]

    if not commit:
        return {
            "ok": True,
            "commit": False,
            "dry_run": True,
            "seed": str(path),
            "entry_count": len(entries),
            "embedding_model": embedding_model,
            "execution_authority": "NONE",
            "can_execute": False,
        }

    dim, existing_dims = _verify_embedding_compatibility(
        db,
        client=client,
        embedding_model=embedding_model,
    )
    memory = Memory(
        str(db),
        embedder=lambda text: client.embed(text, model=embedding_model),
    )
    ids: list[int] = []
    try:
        for entry in entries:
            kwargs = {
                "namespace": entry["namespace"],
                "tags": entry["tags"],
                "mtype": entry["type"],
            }
            if entry["key"] is not None:
                rid = memory.upsert(entry["text"], key=entry["key"], **kwargs)
            else:
                rid = memory.remember(entry["text"], **kwargs)
            ids.append(int(rid))
    finally:
        _close_memory(memory)

    manifest = _write_manifest(db, embedding_model=embedding_model, embedding_dimension=dim)
    return {
        "ok": True,
        "commit": True,
        "dry_run": False,
        "seed": str(path),
        "entry_count": len(entries),
        "stored_ids": ids,
        "embedding_model": embedding_model,
        "embedding_dimension": dim,
        "existing_vector_dimensions_before": existing_dims,
        "memory": memory_report(str(db)),
        "manifest": manifest,
        "execution_authority": "NONE",
        "can_execute": False,
    }
