"""Read-only RUAP Snapshot IR portability for ContinuityOS.

This module is intentionally pure and stdlib-only. It does not perform network
I/O, provider mutation, current-truth promotion, credential reads, deployment,
trading, or capital effects.

RUAP snapshots are imported as EVIDENCE_ONLY portable context. A snapshot is
never execution authority merely because it is syntactically valid or newer.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping, Sequence


RUAP_SNAPSHOT_SCHEMA = "ruap.snapshot/v1"
REQUIRED_AUTHORITY_CEILING = "OBSERVE_ONLY"

_ALLOWED_OBSERVATION_CLASSES = frozenset(
    {
        "PROVIDER_READBACK",
        "ACCEPTED_META",
        "RECEIPT",
        "HANDOFF",
        "HISTORICAL",
        "INFERENCE",
        "UNKNOWN",
    }
)


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: tuple[str, ...]
    canonical_sha256: str | None = None


@dataclass(frozen=True)
class PortableContextEvidence:
    schema: str
    generated_at: str
    authority_ceiling: str
    authority_class: str
    snapshot_sha256: str
    source_count: int
    observation_count: int
    freshness_required: bool
    canonical_snapshot: bytes


@dataclass(frozen=True)
class ContextDelta:
    old_sha256: str
    new_sha256: str
    added_source_ids: tuple[str, ...]
    removed_source_ids: tuple[str, ...]
    added_observation_digests: tuple[str, ...]
    removed_observation_digests: tuple[str, ...]


def _load_snapshot(snapshot_bytes: bytes | str) -> tuple[dict[str, Any] | None, list[str]]:
    if isinstance(snapshot_bytes, bytes):
        try:
            text = snapshot_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None, ["snapshot_not_utf8"]
    elif isinstance(snapshot_bytes, str):
        text = snapshot_bytes
    else:
        return None, ["snapshot_not_bytes_or_text"]

    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None, ["snapshot_invalid_json"]
    if not isinstance(value, dict):
        return None, ["snapshot_root_not_object"]
    return value, []


def _canonical_bytes(snapshot: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            snapshot,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _required_text(obj: Mapping[str, Any], key: str, prefix: str, errors: list[str]) -> str | None:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{prefix}_missing_or_invalid_{key}")
        return None
    return value


def validate_ruap_snapshot(snapshot_bytes: bytes | str) -> ValidationResult:
    snapshot, errors = _load_snapshot(snapshot_bytes)
    if snapshot is None:
        return ValidationResult(False, tuple(errors), None)

    if snapshot.get("schema") != RUAP_SNAPSHOT_SCHEMA:
        errors.append("unsupported_schema")

    if snapshot.get("authority_ceiling") != REQUIRED_AUTHORITY_CEILING:
        errors.append("authority_ceiling_not_observe_only")

    _required_text(snapshot, "generated_at", "snapshot", errors)

    sources = snapshot.get("sources")
    if not isinstance(sources, list):
        errors.append("sources_not_array")
        sources = []

    source_ids: list[str] = []
    for index, source in enumerate(sources):
        prefix = f"source_{index}"
        if not isinstance(source, dict):
            errors.append(f"{prefix}_not_object")
            continue
        source_id = _required_text(source, "id", prefix, errors)
        _required_text(source, "provider", prefix, errors)
        _required_text(source, "locator", prefix, errors)
        _required_text(source, "observed_at", prefix, errors)
        if source_id is not None:
            source_ids.append(source_id)

    if len(source_ids) != len(set(source_ids)):
        errors.append("duplicate_source_id")
    source_id_set = set(source_ids)

    observations = snapshot.get("observations")
    if not isinstance(observations, list):
        errors.append("observations_not_array")
        observations = []

    for index, observation in enumerate(observations):
        prefix = f"observation_{index}"
        if not isinstance(observation, dict):
            errors.append(f"{prefix}_not_object")
            continue
        _required_text(observation, "subject", prefix, errors)
        _required_text(observation, "claim", prefix, errors)
        observation_class = _required_text(observation, "class", prefix, errors)
        source_id = _required_text(observation, "source_id", prefix, errors)
        if observation_class is not None and observation_class not in _ALLOWED_OBSERVATION_CLASSES:
            errors.append(f"{prefix}_unsupported_class")
        if source_id is not None and source_id not in source_id_set:
            errors.append(f"{prefix}_unknown_source_id")

    # Optional root effect-authority fields are accepted only when they
    # explicitly preserve the observe-only boundary. Missing fields remain
    # valid for schema compatibility; present fields fail closed on wrong type
    # or any value other than the exact safe value.
    safe_root_effect_authority: dict[str, Any] = {
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }
    for key, safe_value in safe_root_effect_authority.items():
        if key not in snapshot:
            continue
        value = snapshot[key]
        if type(value) is not type(safe_value):
            errors.append(f"root_effect_authority_invalid_type:{key}")
        elif value != safe_value:
            errors.append(f"root_effect_authority_not_safe:{key}")

    if errors:
        return ValidationResult(False, tuple(errors), None)

    canonical = _canonical_bytes(snapshot)
    return ValidationResult(True, (), sha256(canonical).hexdigest())


def import_ruap_snapshot(snapshot_bytes: bytes | str) -> PortableContextEvidence:
    validation = validate_ruap_snapshot(snapshot_bytes)
    if not validation.ok:
        raise ValueError("invalid RUAP snapshot: " + ",".join(validation.errors))

    snapshot, errors = _load_snapshot(snapshot_bytes)
    assert snapshot is not None and not errors
    canonical = _canonical_bytes(snapshot)
    digest = sha256(canonical).hexdigest()
    observations = snapshot["observations"]

    freshness_required = any(
        observation.get("freshness_required_before_effect") is True
        for observation in observations
        if isinstance(observation, dict)
    )

    return PortableContextEvidence(
        schema=RUAP_SNAPSHOT_SCHEMA,
        generated_at=snapshot["generated_at"],
        authority_ceiling=REQUIRED_AUTHORITY_CEILING,
        authority_class="EVIDENCE_ONLY",
        snapshot_sha256=digest,
        source_count=len(snapshot["sources"]),
        observation_count=len(observations),
        freshness_required=freshness_required,
        canonical_snapshot=canonical,
    )


def export_ruap_snapshot(
    *,
    generated_at: str,
    sources: Sequence[Mapping[str, Any]],
    observations: Sequence[Mapping[str, Any]],
) -> bytes:
    """Export selected ContinuityOS evidence/context as RUAP Snapshot IR.

    Callers must explicitly select sources/observations. This function does not
    read a database, provider, environment variable, credential, or network.
    """
    snapshot = {
        "schema": RUAP_SNAPSHOT_SCHEMA,
        "generated_at": generated_at,
        "authority_ceiling": REQUIRED_AUTHORITY_CEILING,
        "sources": [dict(item) for item in sources],
        "observations": [dict(item) for item in observations],
    }
    canonical = _canonical_bytes(snapshot)
    validation = validate_ruap_snapshot(canonical)
    if not validation.ok:
        raise ValueError("invalid RUAP export: " + ",".join(validation.errors))
    return canonical


def _observation_digest(observation: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        dict(observation),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def diff_ruap_snapshots(old: bytes | str, new: bytes | str) -> ContextDelta:
    old_evidence = import_ruap_snapshot(old)
    new_evidence = import_ruap_snapshot(new)

    old_snapshot = json.loads(old_evidence.canonical_snapshot)
    new_snapshot = json.loads(new_evidence.canonical_snapshot)

    old_source_ids = {source["id"] for source in old_snapshot["sources"]}
    new_source_ids = {source["id"] for source in new_snapshot["sources"]}

    old_observations = {_observation_digest(item) for item in old_snapshot["observations"]}
    new_observations = {_observation_digest(item) for item in new_snapshot["observations"]}

    return ContextDelta(
        old_sha256=old_evidence.snapshot_sha256,
        new_sha256=new_evidence.snapshot_sha256,
        added_source_ids=tuple(sorted(new_source_ids - old_source_ids)),
        removed_source_ids=tuple(sorted(old_source_ids - new_source_ids)),
        added_observation_digests=tuple(sorted(new_observations - old_observations)),
        removed_observation_digests=tuple(sorted(old_observations - new_observations)),
    )
