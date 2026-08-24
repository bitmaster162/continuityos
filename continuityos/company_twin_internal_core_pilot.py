from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .company_twin import replay, validate_dataset
from .company_twin_console import build_snapshot, synthetic_demo_bundle, validate_bundle
from .company_twin_ingest import ENVELOPE_SCHEMA_VERSION, InMemoryIngestStore, to_company_twin_evidence

PILOT_SCHEMA_VERSION = "company-twin-p2e-r3-internal-core/1"
SOURCE_BOUNDARY = "SELECTED_INTERNAL_CORE_ONE_FILE_REDACTED_CHUNKED"
SOURCE_TYPE = "google_drive_selected_internal_file"
TENANT_ID = "tenant_continuityos_lab"
CONNECTOR_ID = "drive-internal-core-p2e-r3"
SOURCE_SYSTEM = "google_drive_internal_core_redacted"
SOURCE_AUTHORITY_ID = "auth_drive_internal_core_p2e_r3"
SOURCE_SCOPE = "team:engineering"
SELECTED_SOURCE_LOCATOR_HASH = "cdb473d8a8fa4da16126493bd5e87c387b70ed21bc75eaa9d0a5493f47f2b8a5"
SELECTED_FILE_NAME = "ContinuityOS_Core.md"
SELECTED_MIME_TYPE = "text/markdown"
MAX_SOURCE_BYTES = 1_000_000
MAX_SANITIZED_CHARS = 20_000
MIN_SANITIZED_CHARS = 800
CHUNK_TARGET_CHARS = 700
CHUNK_MAX_CHARS = 950
CHUNK_MIN_CHARS = 180

_ALLOWED = frozenset({
    "source_type", "source_locator_hash", "file_name", "mime_type", "size_bytes",
    "source_observed_at", "source_modified_at", "document_title", "language",
    "excerpt_kind", "redaction_profile", "sanitized_markdown", "sanitized_document_digest",
})
_FORBIDDEN_KEYS = frozenset({
    "id", "file_id", "folder_id", "drive_id", "url", "web_url", "web_view_link",
    "parents", "parent_ids", "owner", "owners", "owner_email", "email", "permissions",
    "permission_ids", "shared", "sharing_user", "oauth", "authorization", "credential",
    "credentials", "access_token", "refresh_token", "client_secret", "cookie",
})
_FORBIDDEN_FRAGMENTS = ("access_token", "refresh_token", "client_secret", "private_key", "access_key", "credential", "owner_email")
_FORBIDDEN_HOSTS = ("drive.google.com", "docs.google.com")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EMAIL = re.compile(r"(?i)(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Z]{2,}(?![\w.-])")
_SECRET_ASSIGNMENT = re.compile(r"(?i)\b(api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|password)\s*[:=]\s*[^\s,;]{6,}")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_GOOGLE_TOKEN = re.compile(r"(?i)\bya29\.[A-Za-z0-9._-]+")
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.MULTILINE)
_PRIVATE_KEY_MARKER = "-" * 5 + "BEGIN " + "PRIVATE" + " KEY" + "-" * 5


class InternalCorePilotError(ValueError):
    pass


def _canon(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


def _text_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise InternalCorePilotError("timestamp required")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise InternalCorePilotError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise InternalCorePilotError("timestamp requires timezone")
    return parsed.astimezone(timezone.utc)


def _norm_key(value: object) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _bad_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = _norm_key(key)
            if normalized in _FORBIDDEN_KEYS or any(fragment in normalized for fragment in _FORBIDDEN_FRAGMENTS) or _bad_key(child):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_bad_key(child) for child in value)
    return False


def _bad_value(value: Any) -> bool:
    if isinstance(value, str):
        lowered = value.lower()
        return (
            any(host in lowered for host in _FORBIDDEN_HOSTS)
            or bool(_EMAIL.search(value))
            or bool(_SECRET_ASSIGNMENT.search(value))
            or bool(_BEARER.search(value))
            or bool(_GOOGLE_TOKEN.search(value))
            or _PRIVATE_KEY_MARKER in value
        )
    if isinstance(value, Mapping):
        return any(_bad_value(child) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_bad_value(child) for child in value)
    return False


def normalize_markdown(value: str) -> str:
    if not isinstance(value, str):
        raise InternalCorePilotError("sanitized_markdown must be text")
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    text = re.sub(r"\n{4,}", "\n\n\n", text).strip()
    if not text:
        raise InternalCorePilotError("sanitized_markdown must not be empty")
    return text + "\n"


def _artifact_basis(artifact: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("file_name", "mime_type", "size_bytes", "source_observed_at", "source_modified_at", "document_title", "language", "excerpt_kind", "redaction_profile", "sanitized_markdown")
    return {key: copy.deepcopy(artifact[key]) for key in keys}


def sanitize_internal_core_artifact(artifact: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(artifact, Mapping):
        raise InternalCorePilotError("artifact must be object")
    if _bad_key(artifact) or _bad_value(artifact):
        raise InternalCorePilotError("private Drive/PII/credential material rejected")
    if artifact.get("source_type") != SOURCE_TYPE:
        raise InternalCorePilotError("unsupported source_type")
    locator = artifact.get("source_locator_hash")
    if not isinstance(locator, str) or not _HEX64.fullmatch(locator) or locator != SELECTED_SOURCE_LOCATOR_HASH:
        raise InternalCorePilotError("source outside one-file allowlist")
    if artifact.get("file_name") != SELECTED_FILE_NAME or artifact.get("mime_type") != SELECTED_MIME_TYPE:
        raise InternalCorePilotError("selected source identity mismatch")
    size = artifact.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_SOURCE_BYTES:
        raise InternalCorePilotError("invalid bounded source size")
    observed = _time(str(artifact.get("source_observed_at", "")))
    modified = _time(str(artifact.get("source_modified_at", "")))
    if modified > observed:
        raise InternalCorePilotError("source modified after observed snapshot")
    for field in ("document_title", "language", "excerpt_kind", "redaction_profile"):
        if not isinstance(artifact.get(field), str) or not str(artifact[field]).strip():
            raise InternalCorePilotError(f"{field} required")
    markdown = normalize_markdown(str(artifact.get("sanitized_markdown", "")))
    if not MIN_SANITIZED_CHARS <= len(markdown) <= MAX_SANITIZED_CHARS:
        raise InternalCorePilotError("sanitized excerpt outside bounded size")
    if len(markdown.encode("utf-8")) >= size:
        raise InternalCorePilotError("fixture must be a bounded excerpt, not the full raw source")
    if _bad_value(markdown):
        raise InternalCorePilotError("sanitized excerpt contains private material")
    safe = {key: copy.deepcopy(artifact[key]) for key in _ALLOWED if key in artifact and key not in {"sanitized_markdown", "sanitized_document_digest"}}
    safe["sanitized_markdown"] = markdown
    expected = _digest(_artifact_basis(safe))
    supplied = artifact.get("sanitized_document_digest")
    if supplied is not None and (not isinstance(supplied, str) or not _HEX64.fullmatch(supplied) or supplied != expected):
        raise InternalCorePilotError("sanitized_document_digest mismatch")
    safe["sanitized_document_digest"] = expected
    return safe


def _heading_path_at(markdown: str, position: int) -> list[str]:
    levels: list[str | None] = [None] * 6
    for match in _HEADING.finditer(markdown):
        if match.start() > position:
            break
        level = len(match.group(1))
        levels[level - 1] = match.group(2).strip()
        for index in range(level, 6):
            levels[index] = None
    return [item for item in levels if item]


def _preferred_breaks(markdown: str) -> list[int]:
    points = {0, len(markdown)}
    points.update(match.end() for match in re.finditer(r"\n{2,}", markdown))
    points.update(match.start() for match in _HEADING.finditer(markdown))
    return sorted(points)


def chunk_sanitized_markdown(artifact: Mapping[str, Any]) -> list[dict[str, Any]]:
    safe = sanitize_internal_core_artifact(artifact)
    markdown = safe["sanitized_markdown"]
    breaks = _preferred_breaks(markdown)
    chunks: list[dict[str, Any]] = []
    position = 0
    total = len(markdown)
    while position < total:
        while position < total and markdown[position].isspace():
            position += 1
        if position >= total:
            break
        remaining = total - position
        if remaining <= CHUNK_MAX_CHARS:
            headings = [match.start() for match in _HEADING.finditer(markdown, position + 1, total) if match.start() >= position + CHUNK_MIN_CHARS]
            end = min(headings) if headings else total
        else:
            target = min(position + CHUNK_TARGET_CHARS, total)
            cap = min(position + CHUNK_MAX_CHARS, total)
            lower = min(position + CHUNK_MIN_CHARS, total)
            before = [point for point in breaks if lower <= point <= target]
            after = [point for point in breaks if target < point <= cap]
            if before:
                end = max(before)
            elif after:
                end = min(after)
            else:
                end = max(markdown.rfind("\n", lower, cap), markdown.rfind(" ", lower, cap))
                if end <= position:
                    end = cap
        while end > position and markdown[end - 1].isspace():
            end -= 1
        if end <= position:
            raise InternalCorePilotError("chunker failed to make progress")
        text = markdown[position:end]
        index = len(chunks)
        chunk_digest = _text_digest(text)
        chunks.append({
            "chunk_id": "corechunk_" + _text_digest(f"{safe['source_locator_hash']}:{index}")[:24],
            "chunk_index": index,
            "char_start": position,
            "char_end": end,
            "heading_path": _heading_path_at(markdown, position),
            "chunk_digest": chunk_digest,
            "parent_document_digest": safe["sanitized_document_digest"],
            "text": text,
        })
        position = end
    if not chunks:
        raise InternalCorePilotError("chunker produced no chunks")
    count = len(chunks)
    for chunk in chunks:
        chunk["chunk_count"] = count
    return chunks


def artifact_to_envelopes(artifact: Mapping[str, Any]) -> list[dict[str, Any]]:
    safe = sanitize_internal_core_artifact(artifact)
    chunks = chunk_sanitized_markdown(safe)
    locator = safe["source_locator_hash"]
    doc_digest = safe["sanitized_document_digest"]
    cursor = "drive-core:" + doc_digest[:32]
    envelopes = []
    for chunk in chunks:
        payload = {
            "title": safe["document_title"], "file_name": safe["file_name"], "mime_type": safe["mime_type"],
            "source_boundary": SOURCE_BOUNDARY, "parent_source_locator_hash": locator,
            "parent_document_digest": doc_digest, "source_modified_at": safe["source_modified_at"],
            "excerpt_kind": safe["excerpt_kind"], "redaction_profile": safe["redaction_profile"],
            "chunk_id": chunk["chunk_id"], "chunk_index": chunk["chunk_index"], "chunk_count": chunk["chunk_count"],
            "char_start": chunk["char_start"], "char_end": chunk["char_end"], "heading_path": copy.deepcopy(chunk["heading_path"]),
            "chunk_digest": chunk["chunk_digest"], "text": chunk["text"],
        }
        envelopes.append({
            "schema_version": ENVELOPE_SCHEMA_VERSION, "tenant_id": TENANT_ID, "connector_id": CONNECTOR_ID,
            "source_system": SOURCE_SYSTEM, "source_object_type": "selected_internal_core_chunk",
            "source_object_id": chunk["chunk_id"], "revision_id": "doc_" + doc_digest[:16] + "_chunk_" + chunk["chunk_digest"][:16],
            "observed_at": safe["source_observed_at"], "effective_at": safe["source_modified_at"],
            "acl": {"visibility": "TEAM", "scope": SOURCE_SCOPE}, "payload": payload,
            "raw_ref": f"drive-sha256:{locator}#chunk={chunk['chunk_index']:04d}", "cursor": cursor,
            "actor": {"actor_id": "service:drive-internal-core-p2e-r3", "actor_kind": "SERVICE", "role": "SOURCE_SERVICE", "authority_class": "READ_ONLY"},
            "deleted": False,
        })
    return envelopes


def ingest_internal_core_artifact(artifact: Mapping[str, Any], *, store: InMemoryIngestStore | None = None):
    envelopes = artifact_to_envelopes(artifact)
    target = store or InMemoryIngestStore()
    result = target.apply_batch(envelopes, tenant_id=TENANT_ID, connector_id=CONNECTOR_ID, cursor_after=envelopes[0]["cursor"])
    return target, result


def _latest_active_chunks(records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    candidates = [record for record in records if not record.get("deleted") and record.get("source_system") == SOURCE_SYSTEM and record.get("source_object_type") == "selected_internal_core_chunk"]
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for record in candidates:
        grouped.setdefault(str(record["source_object_id"]), []).append(record)
    latest = [max(group, key=lambda record: (_time(str(record["observed_at"])), str(record["revision_id"]))) for group in grouped.values()]
    latest.sort(key=lambda record: int(record["payload"]["chunk_index"]))
    if not latest:
        raise InternalCorePilotError("no active internal core chunks")
    if [int(record["payload"]["chunk_index"]) for record in latest] != list(range(len(latest))):
        raise InternalCorePilotError("chunk indexes must be contiguous")
    counts = {int(record["payload"]["chunk_count"]) for record in latest}
    digests = {str(record["payload"]["parent_document_digest"]) for record in latest}
    locators = {str(record["payload"]["parent_source_locator_hash"]) for record in latest}
    if counts != {len(latest)} or len(digests) != 1 or locators != {SELECTED_SOURCE_LOCATOR_HASH}:
        raise InternalCorePilotError("parent/chunk provenance mismatch")
    return latest


def project_internal_core_to_company_twin(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    active = _latest_active_chunks(records)
    evidence = [to_company_twin_evidence(record, source_authority_id=SOURCE_AUTHORITY_ID) for record in active]
    first = active[0]
    payload = first["payload"]
    effective = str(first["effective_at"])
    observed = max(str(record["observed_at"]) for record in active)
    evidence_ids = [item["id"] for item in evidence]
    by_heading: dict[tuple[str, ...], list[str]] = {}
    for record, item in zip(active, evidence):
        path = tuple(str(value) for value in record["payload"].get("heading_path", []))
        by_heading.setdefault(path, []).append(item["id"])
    observations = [{
        "id": f"proc_internal_core_section_{index:02d}",
        "title": "Selected internal core evidence includes source section: " + (" > ".join(path) if path else "document root"),
        "observed_at": effective, "scope": SOURCE_SCOPE, "truth_class": "FACT", "evidence_ids": sorted(ids),
    } for index, (path, ids) in enumerate(sorted(by_heading.items(), key=lambda item: item[0]))]
    principals = [
        {"id": "principal_director", "name": "ContinuityOS Director", "role": "DIRECTOR", "scopes": ["company", "team:engineering", "team:operations", "restricted:finance"]},
        {"id": "principal_eng_worker", "name": "Engineering Worker", "role": "WORKER", "scopes": ["company", "team:engineering"]},
        {"id": "principal_ops_worker", "name": "Operations Worker", "role": "WORKER", "scopes": ["company", "team:operations"]},
        {"id": "principal_research_robot", "name": "Research Robot", "role": "AGENT", "scopes": ["company", "team:engineering"]},
    ]
    dataset = {
        "schema_version": "company-twin-p2a/1",
        "organization": {"id": "org_continuityos_lab", "name": "ContinuityOS Lab", "industry": "AI infrastructure", "synthetic": False, "source_boundary": SOURCE_BOUNDARY},
        "period": {"start": effective, "end": observed},
        "source_authorities": [{"id": SOURCE_AUTHORITY_ID, "name": "Selected redacted internal ContinuityOS core evidence", "authority": "SOURCE", "source_locator_hash": str(payload["parent_source_locator_hash"]), "source_boundary": SOURCE_BOUNDARY, "parent_document_digest": str(payload["parent_document_digest"])}],
        "principals": principals,
        "entities": [
            {"id": "ent_continuityos_lab", "type": "organization", "name": "ContinuityOS Lab", "created_at": effective, "scope": SOURCE_SCOPE, "truth_class": "FACT"},
            {"id": "ent_internal_continuityos_core", "type": "document", "name": str(payload["title"]), "created_at": effective, "scope": SOURCE_SCOPE, "truth_class": "FACT"},
        ],
        "relationships": [{"id": "rel_internal_core_part_of_lab", "from_entity_id": "ent_internal_continuityos_core", "to_entity_id": "ent_continuityos_lab", "relation": "PART_OF", "effective_from": effective, "scope": SOURCE_SCOPE, "truth_class": "FACT"}],
        "evidence": evidence,
        "events": [{"id": "evt_internal_core_selected_snapshot", "title": "Selected internal ContinuityOS core source recorded as bounded chunked evidence", "occurred_at": effective, "scope": SOURCE_SCOPE, "truth_class": "FACT", "entity_ids": ["ent_internal_continuityos_core"], "evidence_ids": evidence_ids}],
        "decisions": [], "outcomes": [], "process_observations": observations, "inferences": [],
    }
    validate_dataset(dataset)
    return dataset


def replay_internal_core(records: Sequence[Mapping[str, Any]], *, principal_id: str, as_of: str) -> dict[str, Any]:
    return replay(project_internal_core_to_company_twin(records), principal_id=principal_id, as_of=as_of)


def build_pilot_console_bundle(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    base = synthetic_demo_bundle()
    bundle = {"schema_version": base["schema_version"], "memory": project_internal_core_to_company_twin(records), "policy": copy.deepcopy(base["policy"]), "runtime": copy.deepcopy(base["runtime"]), "proposals": []}
    validate_bundle(bundle)
    return bundle


def build_pilot_console_snapshot(records: Sequence[Mapping[str, Any]], *, principal_id: str, as_of: str) -> dict[str, Any]:
    return build_snapshot(build_pilot_console_bundle(records), principal_id=principal_id, as_of=as_of)


def _real() -> dict[str, Any]:
    artifact = {
        "source_type": SOURCE_TYPE,
        "source_locator_hash": SELECTED_SOURCE_LOCATOR_HASH,
        "file_name": SELECTED_FILE_NAME,
        "mime_type": SELECTED_MIME_TYPE,
        "size_bytes": 111562,
        "source_observed_at": "2026-08-21T18:53:13.329Z",
        "source_modified_at": "2026-07-06T21:27:17.308Z",
        "document_title": "ContinuityOS Core & Ecosystem",
        "language": "mixed",
        "excerpt_kind": "sanitized_bounded_internal_excerpt",
        "redaction_profile": "P2E_R3_STRICT_NO_PROVIDER_IDS_NO_PII_NO_CREDENTIALS",
        "sanitized_markdown": """# ContinuityOS Core & Ecosystem

## Source section: AUDIT_DEVIL_2026-06-17

The internal audit describes ContinuityOS as a local-first system spanning memory, continuity, twin, governance and control layers. It records that the early implementation was still an MVP and that several product claims required stronger technical proof.

The audit identifies concrete weaknesses: the default hashing embedder is not true semantic retrieval; brute-force vector search will not scale indefinitely; twin prediction and alignment were heuristic; council identities were not persistent; SQLite remained a single-writer constraint; and the product had not yet proved distribution or user demand.

The same section recommends a small set of corrective moves: add a real optional local embedder and ANN index, benchmark recall quality, strengthen persistent actor identity and auditability, and ship public proof rather than adding architecture indefinitely.

## Source section: AUDIT_GATEWAY_DEVIL_2026-06-17

The gateway audit records adversarial failures in command classification and warns that a benchmark built from the same rules as the classifier can overstate safety. It also states that continuity context had not yet been wired into the preflight path, that rollback inventory was not equivalent to a recoverable snapshot, and that cooperative hooks are weaker than enforced isolation.

The audit treats those findings as evidence for stricter fail-closed governance, stronger policy enforcement and test sets that include adversarial bypass attempts instead of only expected happy paths.

## Source section: product direction

Across the compiled guide, the recurring product direction is to distinguish ContinuityOS from generic agent memory by combining durable state, continuity, evidence-grounded twin behavior and auditable governance. The document repeatedly emphasizes proof, provenance and bounded authority rather than autonomous execution.

The selected P2E-R3 fixture intentionally preserves only these bounded, source-attributable statements. It does not preserve the full internal document, personal metadata, provider identifiers, credentials, private links, customer data or operational secrets.""",
    }
    artifact["sanitized_markdown"] = normalize_markdown(artifact["sanitized_markdown"])
    artifact["sanitized_document_digest"] = _digest(_artifact_basis(artifact))
    return artifact


REAL_INTERNAL_CORE_ARTIFACT = _real()


def source_fixture_document() -> dict[str, Any]:
    return {"schema_version": PILOT_SCHEMA_VERSION, "source_boundary": SOURCE_BOUNDARY, "artifact_count": 1, "artifact": copy.deepcopy(REAL_INTERNAL_CORE_ARTIFACT)}


def load_source_fixture(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping) or data.get("schema_version") != PILOT_SCHEMA_VERSION or data.get("source_boundary") != SOURCE_BOUNDARY or data.get("artifact_count") != 1:
        raise InternalCorePilotError("source fixture boundary mismatch")
    output = {"schema_version": PILOT_SCHEMA_VERSION, "source_boundary": SOURCE_BOUNDARY, "artifact_count": 1, "artifact": sanitize_internal_core_artifact(data.get("artifact", {}))}
    if output != source_fixture_document():
        raise InternalCorePilotError("source fixture differs from pinned sanitized artifact")
    return output
