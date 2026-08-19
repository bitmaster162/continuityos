"""Read-only compatibility audit for Sovereign Twin canonical memory."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .store import Store
from .sovereign_twin_runtime import (
    DEFAULT_EMBEDDING_MODEL,
    LmStudioClient,
    NOMIC_DOCUMENT_TASK,
    NOMIC_QUERY_TASK,
)


def _read_manifest(db: Path) -> tuple[dict[str, Any] | None, str | None, str | None]:
    # R8+ target-specific sidecar avoids accidentally binding a not-yet-switched
    # canonical DB. Fall back to the legacy shared manifest only when it explicitly
    # names this exact DB path.
    candidates = [
        db.with_name(db.stem + ".manifest.json"),
        db.parent / "twin-memory-manifest.json",
    ]
    for path in candidates:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            return None, f"MANIFEST_INVALID:{type(exc).__name__}", str(path)
        if not isinstance(raw, dict):
            return None, "MANIFEST_INVALID:NOT_OBJECT", str(path)
        manifest_db = raw.get("db")
        if manifest_db is not None:
            try:
                manifest_db_path = Path(str(manifest_db)).expanduser().resolve()
            except Exception:
                return None, "MANIFEST_INVALID:DB_PATH", str(path)
            if manifest_db_path != db.resolve():
                if path.name == "twin-memory-manifest.json":
                    continue
                return raw, "MANIFEST_DB_PATH_MISMATCH", str(path)
        return raw, None, str(path)
    return None, None, None


def memory_compatibility_report(
    db_path: str,
    *,
    client: LmStudioClient,
    embedding_model: str = DEFAULT_EMBEDDING_MODEL,
) -> dict[str, Any]:
    """Compare stored vector dimensions and manifest contract with local embeddings.

    This function never mutates canonical memory. Matching dimensions alone do not prove
    identical embedding semantics; an exact model + task-prefix manifest bind is required.
    """
    db = Path(db_path).expanduser()
    if not db.exists():
        return {
            "ok": False,
            "verdict": "MEMORY_DB_MISSING",
            "db": str(db),
            "execution_authority": "NONE",
            "can_execute": False,
            "canonical_memory_mutated": False,
        }

    probe = client.embed(
        "Sovereign Twin memory compatibility probe",
        model=embedding_model,
        task=NOMIC_QUERY_TASK,
    )
    selected_dim = len(probe)
    if selected_dim <= 0:
        raise ValueError("embedding probe returned an empty vector")

    store = Store(str(db), read_only=True)
    try:
        rows = store.con.execute("SELECT vec FROM items").fetchall()
        dims = Counter()
        vectorless = 0
        for row in rows:
            vec = row["vec"]
            if vec is None:
                vectorless += 1
            else:
                dims[len(vec) // 4] += 1
        namespaces = store.namespaces()
    finally:
        store.con.close()

    dimension_counts = {str(k): dims[k] for k in sorted(dims)}
    existing_dims = sorted(dims)
    manifest, manifest_error, manifest_path = _read_manifest(db)
    warnings: list[str] = []
    if manifest_error:
        warnings.append(manifest_error)

    expected_contract = {
        "document_task_prefix": NOMIC_DOCUMENT_TASK,
        "query_task_prefix": NOMIC_QUERY_TASK,
    }
    manifest_bound = False
    if manifest is not None and not manifest_error:
        manifest_bound = (
            manifest.get("embedding_model") == embedding_model
            and manifest.get("embedding_dimension") == selected_dim
            and manifest.get("embedding_contract") == expected_contract
        )
        if not manifest_bound:
            warnings.append("MEMORY_MANIFEST_DOES_NOT_BIND_SELECTED_EMBEDDING_CONTRACT")

    if len(existing_dims) > 1:
        verdict = "BLOCKED_MIXED_VECTOR_DIMENSIONS"
        ok = False
    elif existing_dims and existing_dims[0] != selected_dim:
        verdict = "REEMBED_REQUIRED_DIMENSION_MISMATCH"
        ok = False
    elif not existing_dims:
        verdict = "READY_NO_STORED_VECTORS"
        ok = True
    elif manifest_bound:
        verdict = "COMPATIBLE_MANIFEST_BOUND"
        ok = True
    else:
        verdict = "DIMENSION_MATCH_UNBOUND_SEMANTICS"
        ok = False
        warnings.append("MATCHING_DIMENSION_DOES_NOT_PROVE_SAME_EMBEDDING_CONTRACT")

    return {
        "ok": ok,
        "verdict": verdict,
        "db": str(db),
        "item_count": len(rows),
        "vector_count": sum(dims.values()),
        "vectorless_count": vectorless,
        "vector_dimension_counts": dimension_counts,
        "namespaces": namespaces,
        "selected_embedding_model": embedding_model,
        "selected_embedding_dimension": selected_dim,
        "expected_embedding_contract": expected_contract,
        "manifest": manifest,
        "manifest_path": manifest_path,
        "manifest_bound": manifest_bound,
        "warnings": warnings,
        "execution_authority": "NONE",
        "can_execute": False,
        "canonical_memory_mutated": False,
    }
