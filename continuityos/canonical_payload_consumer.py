"""Fail-closed read-only consumer for the canonical Central Memory payload API."""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
from dataclasses import dataclass
from pathlib import Path
import re
import ssl
from typing import Any, Callable, Mapping, Sequence

SCHEMA = "continuityos.canonical_payload_consumer/v1"
BINDING_SCHEMA = "CONTINUITYOS_CANONICAL_PAYLOAD_BINDING_V1"
CONTEXT_SCHEMA = "CONTINUITYOS_CANONICAL_GOVERNANCE_CONTEXT_V1"
FEATURE_ENV = "CONTINUITYOS_CANONICAL_PAYLOAD_API_ENABLED"
BINDING_ENV = "CONTINUITYOS_CANONICAL_PAYLOAD_BINDING"
BINDING_SHA_ENV = "CONTINUITYOS_CANONICAL_PAYLOAD_BINDING_SHA256"
PASSWORD_ENV = "CONTINUITYOS_CANONICAL_PAYLOAD_PASSWORD"

ORIGIN = "https://archiveos.bitevo.work"
HOST = "archiveos.bitevo.work"
PORT = 443
AUTH_SCHEME = "Basic"
USERNAME = "archiveos"
TIMEOUT_SECONDS = 5

STABLE_SOURCE_ID = "SRC-MEMORY-CANON-CURRENT"
ROLE = "CANONICAL_DECISIONS_PROJECTS_GOVERNANCE"
DISPOSITION = "SELECTED_CURRENT"
CURRENTNESS = "CURRENT_WITHIN_ROLE"
AUTHORITY_UPGRADED = False
RECORD_DIGEST = "0af4470f1bcd0ba6262d46146aad9e966cd5cc2e9848228d037f6dd798c908dd"
PROJECTION_DIGEST = "5e3fa31d28617ee678ee1af109849493c7153df633c2189b32aabe1dffbb2a76"
SNAPSHOT_DIGEST = "6119e89e09e45b2847de1e1914fa16ab06247f123b7982922a616c4392a2c3fa"
DECISION_COUNT = 139
DECISION_RANGE = ("D001", "D139")
PROJECT_COUNT = 10
PROJECT_STATUS_COUNTS = {"CURRENT_TRUNK": 9, "LEGACY_VALID_CONCEPT": 1}
CACHE_CONTROL_TOKENS = frozenset({"private", "no-store"})

HEALTH_PATH = "/central-memory/payload/health"
DECISIONS_PATH = "/central-memory/current/decisions"
PROJECTS_PATH = "/central-memory/current/projects"
DECISION_PATH = "/central-memory/current/decisions/{decision_id}"
PROJECT_PATH = "/central-memory/current/projects/{project_id}"
DECISION_ID_RE = re.compile(r"^D[0-9]{3}$")
PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

HEALTH_MAX_BYTES = 65_536
COLLECTION_MAX_BYTES = 1_048_576
POINT_MAX_BYTES = 262_144


class ConsumerHold(RuntimeError):
    """Fail-closed consumer terminal with bounded, non-secret reason text."""

    def __init__(self, status: str, reason: str, *, http_status: int | None = None):
        super().__init__(f"{status}: {reason}")
        self.status = status
        self.reason = reason
        self.http_status = http_status


@dataclass(frozen=True)
class ConsumerConfig:
    binding: Mapping[str, Any]
    binding_sha256: str
    password: str


def effects(*, network_read: bool = False) -> dict[str, object]:
    return {
        "network_read": network_read,
        "http_method": "GET" if network_read else None,
        "filesystem_write": False,
        "database_write": False,
        "memory_write": False,
        "operational_memory_write": False,
        "subprocess_execution": False,
        "provider_write": False,
        "current_state_apply": False,
        "canonical_mutation": False,
        "execution_authorized": False,
        "authority_upgrade": False,
        "mcp_auto_injection": False,
        "deployment": False,
        "trading": False,
        "wallet_access": False,
        "order_execution": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConsumerHold("HOLD_JSON_INVALID", "duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise ConsumerHold("HOLD_JSON_INVALID", "non-finite JSON constant")


def strict_json_loads(data: bytes) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConsumerHold("HOLD_JSON_INVALID", "response is not UTF-8 JSON") from exc
    try:
        return json.loads(text, object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
    except ConsumerHold:
        raise
    except json.JSONDecodeError as exc:
        raise ConsumerHold("HOLD_JSON_INVALID", "response JSON is invalid") from exc


def _feature_enabled(env: Mapping[str, str]) -> bool:
    raw = env.get(FEATURE_ENV, "0")
    if raw == "0":
        return False
    if raw == "1":
        return True
    raise ConsumerHold("HOLD_CONFIG_INVALID", f"{FEATURE_ENV} must be 0 or 1")


def _canonical_binding_path(raw: str) -> Path:
    if not raw.strip():
        raise ConsumerHold("HOLD_BINDING_UNBOUND", "canonical payload binding path is not bound")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        raise ConsumerHold("HOLD_BINDING_NONCANONICAL", "binding path must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ConsumerHold("HOLD_BINDING_UNAVAILABLE", "binding file is unavailable") from exc
    if candidate.is_symlink() or os.path.normcase(str(candidate)) != os.path.normcase(str(resolved)):
        raise ConsumerHold("HOLD_BINDING_NONCANONICAL", "binding file path is symlinked or non-canonical")
    if not resolved.is_file():
        raise ConsumerHold("HOLD_BINDING_UNAVAILABLE", "binding file is unavailable")
    return resolved


def _require_binding_contract(binding: Any) -> dict[str, Any]:
    if not isinstance(binding, dict):
        raise ConsumerHold("HOLD_BINDING_SCHEMA", "binding must be a JSON object")
    required = {
        "schema": BINDING_SCHEMA,
        "origin": ORIGIN,
        "stable_source_id": STABLE_SOURCE_ID,
        "role": ROLE,
        "resolution_disposition": DISPOSITION,
        "currentness_status": CURRENTNESS,
        "authority_upgraded": AUTHORITY_UPGRADED,
        "record_digest": RECORD_DIGEST,
        "projection_digest": PROJECTION_DIGEST,
        "snapshot_digest": SNAPSHOT_DIGEST,
        "decision_count": DECISION_COUNT,
        "decision_range": list(DECISION_RANGE),
        "project_count": PROJECT_COUNT,
        "project_status_counts": PROJECT_STATUS_COUNTS,
    }
    for key, expected in required.items():
        if binding.get(key) != expected:
            raise ConsumerHold("HOLD_BINDING_IDENTITY_MISMATCH", f"binding field mismatch: {key}")
    auth = binding.get("auth")
    if not isinstance(auth, dict) or auth.get("scheme") != AUTH_SCHEME or auth.get("username") != USERNAME:
        raise ConsumerHold("HOLD_BINDING_IDENTITY_MISMATCH", "binding auth identity mismatch")
    tokens = binding.get("cache_control_required_tokens")
    if not isinstance(tokens, list) or {str(v).lower() for v in tokens} != CACHE_CONTROL_TOKENS:
        raise ConsumerHold("HOLD_BINDING_IDENTITY_MISMATCH", "binding cache-control contract mismatch")
    return dict(binding)


def load_config(env: Mapping[str, str] | None = None) -> ConsumerConfig | None:
    values = os.environ if env is None else env
    if not _feature_enabled(values):
        return None
    expected_sha = values.get(BINDING_SHA_ENV, "")
    if not HEX64_RE.fullmatch(expected_sha):
        raise ConsumerHold("HOLD_BINDING_SHA_UNBOUND", "expected binding SHA-256 is missing or invalid")
    path = _canonical_binding_path(values.get(BINDING_ENV, ""))
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConsumerHold("HOLD_BINDING_UNAVAILABLE", "binding file read failed") from exc
    observed_sha = hashlib.sha256(raw).hexdigest()
    if observed_sha != expected_sha:
        raise ConsumerHold("HOLD_BINDING_SHA_MISMATCH", "binding SHA-256 mismatch")
    binding = _require_binding_contract(strict_json_loads(raw))
    password = values.get(PASSWORD_ENV, "")
    if not password:
        raise ConsumerHold("HOLD_AUTH_UNBOUND", f"{PASSWORD_ENV} is not bound")
    return ConsumerConfig(binding=binding, binding_sha256=observed_sha, password=password)


def _cache_control_tokens(headers: Mapping[str, str]) -> set[str]:
    return {part.strip().lower() for part in headers.get("cache-control", "").split(",") if part.strip()}


def _meta_from_health(doc: Mapping[str, Any]) -> dict[str, Any]:
    return {key: doc.get(key) for key in (
        "stable_source_id", "role", "resolution_disposition", "currentness_status",
        "authority_upgraded", "record_digest", "projection_digest", "snapshot_digest"
    )}


def _validate_meta(meta: Any) -> dict[str, Any]:
    if not isinstance(meta, dict):
        raise ConsumerHold("HOLD_META_MISMATCH", "canonical payload meta is unavailable")
    expected = {
        "stable_source_id": STABLE_SOURCE_ID,
        "role": ROLE,
        "resolution_disposition": DISPOSITION,
        "currentness_status": CURRENTNESS,
        "authority_upgraded": False,
        "record_digest": RECORD_DIGEST,
        "projection_digest": PROJECTION_DIGEST,
        "snapshot_digest": SNAPSHOT_DIGEST,
    }
    for key, value in expected.items():
        if meta.get(key) != value:
            raise ConsumerHold("HOLD_META_MISMATCH", f"canonical payload meta mismatch: {key}")
    return dict(meta)


def _same_meta(*metas: Mapping[str, Any]) -> None:
    if metas and any(dict(meta) != dict(metas[0]) for meta in metas[1:]):
        raise ConsumerHold("HOLD_META_MISMATCH", "canonical payload meta differs across endpoints")


class CanonicalPayloadConsumer:
    """Strict GET-only Central Memory client with ephemeral projection output."""

    def __init__(self, config: ConsumerConfig, *, connection_factory: Callable[..., Any] = http.client.HTTPSConnection) -> None:
        self.config = config
        self._connection_factory = connection_factory

    def _authorization(self) -> str:
        token = base64.b64encode(f"{USERNAME}:{self.config.password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    def _get_json(self, path: str, *, max_bytes: int, expected_statuses: Sequence[int] = (200,)) -> tuple[int, Mapping[str, str], Any]:
        if not path.startswith("/") or "\r" in path or "\n" in path:
            raise ConsumerHold("HOLD_REQUEST_INVALID", "request path is invalid")
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Authorization": self._authorization(),
            "User-Agent": "continuityos-canonical-payload-consumer/1",
        }
        connection = None
        try:
            context = ssl.create_default_context()
            connection = self._connection_factory(HOST, PORT, timeout=TIMEOUT_SECONDS, context=context)
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            status = int(response.status)
            observed_headers = {str(k).lower(): str(v) for k, v in response.getheaders()}
            encoding = observed_headers.get("content-encoding", "identity").strip().lower()
            if encoding not in {"", "identity"}:
                raise ConsumerHold("HOLD_CONTENT_ENCODING", "compressed response content is denied", http_status=status)
            length = observed_headers.get("content-length")
            if length:
                try:
                    declared = int(length)
                except ValueError as exc:
                    raise ConsumerHold("HOLD_RESPONSE_SIZE", "invalid Content-Length") from exc
                if declared < 0 or declared > max_bytes:
                    raise ConsumerHold("HOLD_RESPONSE_SIZE", "response exceeds size limit", http_status=status)
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ConsumerHold("HOLD_RESPONSE_SIZE", "response exceeds size limit", http_status=status)
        except ConsumerHold:
            raise
        except ssl.SSLError as exc:
            raise ConsumerHold("HOLD_TLS_FAILURE", "TLS verification failed") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise ConsumerHold("HOLD_TRANSPORT_FAILURE", "HTTPS transport failed") from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
        if not CACHE_CONTROL_TOKENS.issubset(_cache_control_tokens(observed_headers)):
            raise ConsumerHold("HOLD_CACHE_CONTROL", "required private,no-store cache control is absent", http_status=status)
        doc = strict_json_loads(body)
        if status in (301, 302, 303, 307, 308):
            raise ConsumerHold("HOLD_REDIRECT_DENIED", "redirect response is denied", http_status=status)
        if status in (401, 403):
            raise ConsumerHold("HOLD_AUTH", "canonical payload authentication rejected", http_status=status)
        if status == 503:
            detail = doc.get("detail") if isinstance(doc, dict) else None
            remote = detail.get("status") if isinstance(detail, dict) else None
            remote_status = remote if isinstance(remote, str) and remote else "HOLD_PROVIDER_503"
            raise ConsumerHold(remote_status, "canonical payload provider returned 503", http_status=status)
        if status not in expected_statuses:
            raise ConsumerHold("HOLD_HTTP_STATUS", f"unexpected HTTP status {status}", http_status=status)
        return status, observed_headers, doc

    def health(self) -> dict[str, Any]:
        _, _, doc = self._get_json(HEALTH_PATH, max_bytes=HEALTH_MAX_BYTES)
        if not isinstance(doc, dict):
            raise ConsumerHold("HOLD_HEALTH_MISMATCH", "payload health response must be an object")
        if doc.get("ok") is not True or doc.get("enabled") is not True or doc.get("status") != "READ_ONLY_READY":
            raise ConsumerHold("HOLD_HEALTH_MISMATCH", "payload health is not READ_ONLY_READY")
        meta = _validate_meta(_meta_from_health(doc))
        if doc.get("decision_count") != DECISION_COUNT or doc.get("project_count") != PROJECT_COUNT:
            raise ConsumerHold("HOLD_COUNT_MISMATCH", "payload health count mismatch")
        return {"meta": meta, "decision_count": DECISION_COUNT, "project_count": PROJECT_COUNT}

    def decisions(self) -> dict[str, Any]:
        _, _, doc = self._get_json(DECISIONS_PATH, max_bytes=COLLECTION_MAX_BYTES)
        if not isinstance(doc, dict) or not isinstance(doc.get("records"), list):
            raise ConsumerHold("HOLD_DECISIONS_MISMATCH", "decision collection schema mismatch")
        meta = _validate_meta(doc.get("meta"))
        records = doc["records"]
        if doc.get("count") != DECISION_COUNT or len(records) != DECISION_COUNT or doc.get("range") != list(DECISION_RANGE):
            raise ConsumerHold("HOLD_DECISIONS_MISMATCH", "decision count or range mismatch")
        expected_ids = [f"D{i:03d}" for i in range(1, DECISION_COUNT + 1)]
        ids = [record.get("decision_id") if isinstance(record, dict) else None for record in records]
        if ids != expected_ids or any(not isinstance(record, dict) or record.get("status") != "CURRENT" for record in records):
            raise ConsumerHold("HOLD_DECISIONS_MISMATCH", "decision records are not contiguous CURRENT D001-D139")
        return {"meta": meta, "records": records}

    def projects(self) -> dict[str, Any]:
        _, _, doc = self._get_json(PROJECTS_PATH, max_bytes=COLLECTION_MAX_BYTES)
        if not isinstance(doc, dict) or not isinstance(doc.get("records"), list):
            raise ConsumerHold("HOLD_PROJECTS_MISMATCH", "project collection schema mismatch")
        meta = _validate_meta(doc.get("meta"))
        records = doc["records"]
        if doc.get("count") != PROJECT_COUNT or len(records) != PROJECT_COUNT:
            raise ConsumerHold("HOLD_PROJECTS_MISMATCH", "project count mismatch")
        ids = [record.get("project_id") if isinstance(record, dict) else None for record in records]
        if any(not isinstance(value, str) for value in ids) or len(set(ids)) != PROJECT_COUNT:
            raise ConsumerHold("HOLD_PROJECTS_MISMATCH", "project IDs are not unique")
        counts: dict[str, int] = {}
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("status"), str):
                raise ConsumerHold("HOLD_PROJECTS_MISMATCH", "project record schema mismatch")
            counts[record["status"]] = counts.get(record["status"], 0) + 1
        if counts != PROJECT_STATUS_COUNTS:
            raise ConsumerHold("HOLD_PROJECTS_MISMATCH", "project status counts mismatch")
        return {"meta": meta, "records": records}

    def snapshot(self) -> dict[str, Any]:
        health = self.health()
        decisions = self.decisions()
        projects = self.projects()
        _same_meta(health["meta"], decisions["meta"], projects["meta"])
        value = {
            "schema": SCHEMA,
            "terminal": "CANONICAL_PAYLOAD_SNAPSHOT_PASS",
            "meta": health["meta"],
            "decision_count": DECISION_COUNT,
            "project_count": PROJECT_COUNT,
            "decisions": decisions["records"],
            "projects": projects["records"],
            "effects": effects(network_read=True),
        }
        value["canonical_output_sha256"] = canonical_sha256(value)
        return value

    def context(self) -> dict[str, Any]:
        snapshot = self.snapshot()
        value = {
            "schema": CONTEXT_SCHEMA,
            "mode": "EPHEMERAL_PROJECTION_ONLY",
            "meta": snapshot["meta"],
            "decisions": snapshot["decisions"],
            "projects": snapshot["projects"],
            "effects": effects(network_read=True),
        }
        value["canonical_output_sha256"] = canonical_sha256(value)
        return value

    def decision(self, decision_id: str) -> dict[str, Any]:
        expected = 200 if DECISION_ID_RE.fullmatch(decision_id) else 422
        status, _, doc = self._get_json(DECISION_PATH.format(decision_id=decision_id), max_bytes=POINT_MAX_BYTES, expected_statuses=(200, 404, 422))
        if status == 422:
            if expected != 422:
                raise ConsumerHold("HOLD_POINT_MISMATCH", "provider rejected a valid decision ID", http_status=status)
            return {"status": 422, "terminal": "INVALID_DECISION_ID"}
        if status == 404:
            if expected == 422:
                raise ConsumerHold("HOLD_POINT_MISMATCH", "invalid decision ID did not return 422", http_status=status)
            return {"status": 404, "terminal": "NOT_FOUND"}
        if expected == 422:
            raise ConsumerHold("HOLD_POINT_MISMATCH", "invalid decision ID unexpectedly resolved", http_status=status)
        if not isinstance(doc, dict) or not isinstance(doc.get("record"), dict):
            raise ConsumerHold("HOLD_POINT_MISMATCH", "decision point response schema mismatch")
        meta = _validate_meta(doc.get("meta"))
        record = doc["record"]
        if record.get("decision_id") != decision_id or record.get("status") != "CURRENT":
            raise ConsumerHold("HOLD_POINT_MISMATCH", "decision point identity mismatch")
        return {"status": 200, "meta": meta, "record": record}

    def project(self, project_id: str) -> dict[str, Any]:
        expected = 200 if PROJECT_ID_RE.fullmatch(project_id) else 422
        status, _, doc = self._get_json(PROJECT_PATH.format(project_id=project_id), max_bytes=POINT_MAX_BYTES, expected_statuses=(200, 404, 422))
        if status == 422:
            if expected != 422:
                raise ConsumerHold("HOLD_POINT_MISMATCH", "provider rejected a valid project ID", http_status=status)
            return {"status": 422, "terminal": "INVALID_PROJECT_ID"}
        if status == 404:
            if expected == 422:
                raise ConsumerHold("HOLD_POINT_MISMATCH", "invalid project ID did not return 422", http_status=status)
            return {"status": 404, "terminal": "NOT_FOUND"}
        if expected == 422:
            raise ConsumerHold("HOLD_POINT_MISMATCH", "invalid project ID unexpectedly resolved", http_status=status)
        if not isinstance(doc, dict) or not isinstance(doc.get("record"), dict):
            raise ConsumerHold("HOLD_POINT_MISMATCH", "project point response schema mismatch")
        meta = _validate_meta(doc.get("meta"))
        record = doc["record"]
        if record.get("project_id") != project_id:
            raise ConsumerHold("HOLD_POINT_MISMATCH", "project point identity mismatch")
        return {"status": 200, "meta": meta, "record": record}


def disabled_receipt() -> dict[str, Any]:
    return {"schema": SCHEMA, "terminal": "CANONICAL_PAYLOAD_DISABLED", "status": "DISABLED_DEFAULT", "effects": effects(network_read=False)}


def hold_receipt(exc: ConsumerHold) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": SCHEMA,
        "terminal": "CANONICAL_PAYLOAD_HOLD",
        "status": exc.status,
        "reason": exc.reason,
        "effects": effects(network_read=False),
    }
    if exc.http_status is not None:
        value["http_status"] = exc.http_status
        value["effects"] = effects(network_read=True)
    return value
