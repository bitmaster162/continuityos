from __future__ import annotations

import copy
import inspect
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from .company_twin import replay, validate_dataset
from .company_twin_console import build_snapshot, synthetic_demo_bundle, validate_bundle
from .company_twin_ingest import (
    ENVELOPE_SCHEMA_VERSION,
    InMemoryIngestStore,
    to_company_twin_evidence,
)

PILOT_SCHEMA_VERSION = "company-twin-p2e-r1-public-github/1"
PUBLIC_REPOSITORY = "bitmaster162/continuityos"
TENANT_ID = "tenant_continuityos_lab"
CONNECTOR_ID = "github-public-p2e-r1"
SOURCE_SYSTEM = "github_public"
SOURCE_AUTHORITY_ID = "auth_github_public_p2e_r1"
SOURCE_SCOPE = "team:engineering"

SUPPORTED_ARTIFACT_TYPES = {"issue", "pull_request", "commit", "workflow_run"}
PAYLOAD_ALLOWLIST: dict[str, frozenset[str]] = {
    "issue": frozenset({"number", "title", "state", "created_at", "updated_at"}),
    "pull_request": frozenset({
        "number", "title", "state", "merged", "created_at", "merged_at",
        "head_sha", "base_sha", "merge_commit_sha",
    }),
    "commit": frozenset({"sha", "message", "committed_at", "pull_request_number"}),
    "workflow_run": frozenset({
        "run_id", "name", "run_number", "status", "conclusion", "head_sha",
        "created_at", "completed_at", "display_title", "failing_steps",
    }),
}
PAYLOAD_REQUIRED: dict[str, frozenset[str]] = {
    "issue": frozenset({"number", "title", "state", "created_at"}),
    "pull_request": frozenset({"number", "title", "state", "merged", "created_at", "head_sha"}),
    "commit": frozenset({"sha", "message", "committed_at"}),
    "workflow_run": frozenset({
        "run_id", "name", "run_number", "status", "conclusion", "head_sha",
        "created_at", "completed_at",
    }),
}
SENSITIVE_KEY_FRAGMENTS = (
    "token", "secret", "password", "authorization", "cookie",
    "private_key", "client_secret", "access_key", "credential",
)


class PublicGitHubPilotError(ValueError):
    pass


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PublicGitHubPilotError("timestamp must be a non-empty string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise PublicGitHubPilotError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise PublicGitHubPilotError("timestamp requires timezone")
    return parsed.astimezone(timezone.utc)


def _normalized_key(value: object) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = _normalized_key(key)
            if any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS):
                return True
            if _contains_sensitive_key(nested):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _validate_public_ref(value: str) -> None:
    if not isinstance(value, str) or not value:
        raise PublicGitHubPilotError("raw_ref is required")
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise PublicGitHubPilotError("raw_ref must be a public github.com URL")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise PublicGitHubPilotError("raw_ref must not contain query/auth material")
    prefix = f"/{PUBLIC_REPOSITORY}/"
    if not parsed.path.startswith(prefix):
        raise PublicGitHubPilotError("raw_ref repository mismatch")


def sanitize_public_artifact(artifact: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(artifact, Mapping):
        raise PublicGitHubPilotError("artifact must be an object")
    if _contains_sensitive_key(artifact):
        raise PublicGitHubPilotError("artifact contains secret-like field names")
    artifact_type = str(artifact.get("artifact_type", ""))
    if artifact_type not in SUPPORTED_ARTIFACT_TYPES:
        raise PublicGitHubPilotError("unsupported public GitHub artifact type")
    if artifact.get("repository") != PUBLIC_REPOSITORY:
        raise PublicGitHubPilotError("repository mismatch")
    if artifact.get("public") is not True:
        raise PublicGitHubPilotError("artifact is not explicitly public")
    for field in ("source_id", "revision_id", "observed_at", "effective_at", "raw_ref"):
        if not isinstance(artifact.get(field), str) or not artifact[field]:
            raise PublicGitHubPilotError(f"{field} is required")
    observed = _parse_time(str(artifact["observed_at"]))
    effective = _parse_time(str(artifact["effective_at"]))
    if effective > observed:
        raise PublicGitHubPilotError("effective_at must not be after observed_at")
    _validate_public_ref(str(artifact["raw_ref"]))

    raw_payload = artifact.get("payload")
    if not isinstance(raw_payload, Mapping):
        raise PublicGitHubPilotError("payload must be an object")
    allowed = PAYLOAD_ALLOWLIST[artifact_type]
    payload = {key: copy.deepcopy(raw_payload[key]) for key in allowed if key in raw_payload}
    missing = PAYLOAD_REQUIRED[artifact_type].difference(payload)
    if missing:
        raise PublicGitHubPilotError(
            "payload missing required public fields: " + ", ".join(sorted(missing))
        )

    for field in ("created_at", "updated_at", "merged_at", "committed_at", "completed_at"):
        if field in payload and payload[field] is not None:
            _parse_time(str(payload[field]))

    return {
        "artifact_type": artifact_type,
        "repository": PUBLIC_REPOSITORY,
        "public": True,
        "source_id": str(artifact["source_id"]),
        "revision_id": str(artifact["revision_id"]),
        "observed_at": str(artifact["observed_at"]),
        "effective_at": str(artifact["effective_at"]),
        "raw_ref": str(artifact["raw_ref"]),
        "payload": payload,
    }


def artifact_to_envelope(artifact: Mapping[str, Any], *, cursor: str) -> dict[str, Any]:
    item = sanitize_public_artifact(artifact)
    return {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "tenant_id": TENANT_ID,
        "connector_id": CONNECTOR_ID,
        "source_system": SOURCE_SYSTEM,
        "source_object_type": item["artifact_type"],
        "source_object_id": item["source_id"],
        "revision_id": item["revision_id"],
        "observed_at": item["observed_at"],
        "effective_at": item["effective_at"],
        "acl": {"visibility": "TEAM", "scope": SOURCE_SCOPE},
        "payload": item["payload"],
        "raw_ref": item["raw_ref"],
        "cursor": cursor,
        "actor": {
            "actor_id": "service:github-public-p2e-r1",
            "actor_kind": "SERVICE",
            "role": "SOURCE_SERVICE",
            "authority_class": "READ_ONLY",
        },
        "deleted": False,
    }


def adapt_public_history(artifacts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    sanitized = [sanitize_public_artifact(item) for item in artifacts]
    sanitized.sort(
        key=lambda item: (
            _parse_time(item["effective_at"]),
            item["artifact_type"],
            item["source_id"],
            item["revision_id"],
        )
    )
    return [
        artifact_to_envelope(
            item,
            cursor=f"github-public:{index:04d}:{item['revision_id']}",
        )
        for index, item in enumerate(sanitized, start=1)
    ]


def ingest_public_history(
    artifacts: Sequence[Mapping[str, Any]],
    *,
    store: InMemoryIngestStore | None = None,
):
    envelopes = adapt_public_history(artifacts)
    if not envelopes:
        raise PublicGitHubPilotError("at least one public artifact is required")
    target = store or InMemoryIngestStore()
    result = target.apply_batch(
        envelopes,
        tenant_id=TENANT_ID,
        connector_id=CONNECTOR_ID,
        cursor_after=envelopes[-1]["cursor"],
    )
    return target, result


def _evidence_by_record(records: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    evidence: list[dict[str, Any]] = []
    index: dict[str, str] = {}
    for record in sorted(records, key=lambda item: str(item["id"])):
        item = to_company_twin_evidence(record, source_authority_id=SOURCE_AUTHORITY_ID)
        evidence.append(item)
        index[str(record["id"])] = str(item["id"])
    return evidence, index


def _record_index(records: Sequence[Mapping[str, Any]]) -> dict[tuple[str, str], Mapping[str, Any]]:
    return {
        (str(record["source_object_type"]), str(record["source_object_id"])): record
        for record in records
    }


def project_public_history_to_company_twin(
    records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    active = [record for record in records if not record.get("deleted")]
    evidence, ev_by_record = _evidence_by_record(active)
    by_source = _record_index(active)

    entities = [
        {
            "id": "ent_continuityos_lab",
            "type": "organization",
            "name": "ContinuityOS Lab",
            "created_at": "2026-08-23T23:50:00Z",
            "scope": SOURCE_SCOPE,
            "truth_class": "FACT",
        },
        {
            "id": "ent_continuityos_repo",
            "type": "repository",
            "name": PUBLIC_REPOSITORY,
            "created_at": "2026-08-23T23:50:00Z",
            "scope": SOURCE_SCOPE,
            "truth_class": "FACT",
        },
    ]
    relationships = [
        {
            "id": "rel_repo_part_of_lab",
            "from_entity_id": "ent_continuityos_repo",
            "to_entity_id": "ent_continuityos_lab",
            "relation": "PART_OF",
            "effective_from": "2026-08-23T23:50:00Z",
            "scope": SOURCE_SCOPE,
            "truth_class": "FACT",
        }
    ]

    events: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    def ev_id(record: Mapping[str, Any]) -> str:
        return ev_by_record[str(record["id"])]

    for record in active:
        payload = record["payload"]
        kind = str(record["source_object_type"])
        source_id = str(record["source_object_id"])
        if kind == "issue":
            events.append({
                "id": f"evt_{source_id.replace(':', '_')}_opened",
                "title": f"Issue #{payload['number']} opened: {payload['title']}",
                "occurred_at": str(payload["created_at"]),
                "scope": SOURCE_SCOPE,
                "truth_class": "FACT",
                "entity_ids": ["ent_continuityos_repo"],
                "evidence_ids": [ev_id(record)],
            })
        elif kind == "workflow_run":
            events.append({
                "id": f"evt_{source_id.replace(':', '_')}",
                "title": (
                    f"Workflow {payload['name']} #{payload['run_number']} "
                    f"completed with {payload['conclusion']}"
                ),
                "occurred_at": str(payload["completed_at"]),
                "scope": SOURCE_SCOPE,
                "truth_class": "FACT",
                "entity_ids": ["ent_continuityos_repo"],
                "evidence_ids": [ev_id(record)],
            })
        elif kind == "pull_request" and payload.get("merged") is True and payload.get("merged_at"):
            decisions.append({
                "id": f"dec_merge_pr_{payload['number']}",
                "title": f"Merge PR #{payload['number']}: {payload['title']}",
                "decided_at": str(payload["merged_at"]),
                "scope": SOURCE_SCOPE,
                "truth_class": "FACT",
                "rationale": "GitHub records this pull request as merged; no additional rationale is inferred.",
                "evidence_ids": [ev_id(record)],
                "supersedes": None,
            })
        elif kind == "commit":
            events.append({
                "id": f"evt_commit_{str(payload['sha'])[:12]}",
                "title": f"Commit {str(payload['sha'])[:12]} recorded",
                "occurred_at": str(payload["committed_at"]),
                "scope": SOURCE_SCOPE,
                "truth_class": "FACT",
                "entity_ids": ["ent_continuityos_repo"],
                "evidence_ids": [ev_id(record)],
            })
            pr_number = payload.get("pull_request_number")
            if pr_number is not None and ("pull_request", f"pr:{pr_number}") in by_source:
                outcomes.append({
                    "id": f"out_merge_pr_{pr_number}",
                    "title": f"Merge commit recorded for PR #{pr_number}",
                    "occurred_at": str(payload["committed_at"]),
                    "scope": SOURCE_SCOPE,
                    "truth_class": "FACT",
                    "decision_id": f"dec_merge_pr_{pr_number}",
                    "evidence_ids": [ev_id(record)],
                })

    failed = next(
        (
            record for record in active
            if record["source_object_type"] == "workflow_run"
            and record["payload"].get("display_title") == "P2D: Company Twin Operating Console"
            and record["payload"].get("conclusion") == "failure"
        ),
        None,
    )
    passed = next(
        (
            record for record in active
            if record["source_object_type"] == "workflow_run"
            and record["payload"].get("display_title") == "P2D: Company Twin Operating Console"
            and record["payload"].get("conclusion") == "success"
        ),
        None,
    )
    if failed is not None and passed is not None:
        observations.append({
            "id": "proc_p2d_failure_to_success",
            "title": "P2D qualification progressed from failure to success on a later head",
            "observed_at": str(passed["payload"]["completed_at"]),
            "scope": SOURCE_SCOPE,
            "truth_class": "FACT",
            "evidence_ids": [ev_id(failed), ev_id(passed)],
        })

    dataset = {
        "schema_version": "company-twin-p2a/1",
        "organization": {
            "id": "org_continuityos_lab",
            "name": "ContinuityOS Lab",
            "industry": "AI infrastructure",
            "synthetic": False,
            "source_boundary": "PUBLIC_GITHUB_ONLY",
        },
        "period": {
            "start": "2026-08-23T23:50:00Z",
            "end": "2026-08-24T23:59:59Z",
        },
        "source_authorities": [{
            "id": SOURCE_AUTHORITY_ID,
            "name": "Public GitHub evidence",
            "authority": "SOURCE",
            "repository": PUBLIC_REPOSITORY,
        }],
        "principals": [
            {
                "id": "principal_director",
                "name": "ContinuityOS Director",
                "role": "DIRECTOR",
                "scopes": ["company", "team:engineering", "team:operations", "restricted:finance"],
            },
            {
                "id": "principal_eng_worker",
                "name": "Engineering Worker",
                "role": "WORKER",
                "scopes": ["company", "team:engineering"],
            },
            {
                "id": "principal_ops_worker",
                "name": "Operations Worker",
                "role": "WORKER",
                "scopes": ["company", "team:operations"],
            },
            {
                "id": "principal_research_robot",
                "name": "Research Robot",
                "role": "AGENT",
                "scopes": ["company", "team:engineering"],
            },
        ],
        "entities": sorted(entities, key=lambda item: item["id"]),
        "relationships": sorted(relationships, key=lambda item: item["id"]),
        "evidence": sorted(evidence, key=lambda item: item["id"]),
        "events": sorted(events, key=lambda item: item["id"]),
        "decisions": sorted(decisions, key=lambda item: item["id"]),
        "outcomes": sorted(outcomes, key=lambda item: item["id"]),
        "process_observations": sorted(observations, key=lambda item: item["id"]),
        "inferences": [],
    }
    validate_dataset(dataset)
    return dataset


def replay_public_history(
    records: Sequence[Mapping[str, Any]],
    *,
    principal_id: str,
    as_of: str,
) -> dict[str, Any]:
    return replay(
        project_public_history_to_company_twin(records),
        principal_id=principal_id,
        as_of=as_of,
    )


def build_pilot_console_bundle(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    base = synthetic_demo_bundle()
    bundle = {
        "schema_version": base["schema_version"],
        "memory": project_public_history_to_company_twin(records),
        "policy": copy.deepcopy(base["policy"]),
        "runtime": copy.deepcopy(base["runtime"]),
        "proposals": [],
    }
    validate_bundle(bundle)
    return bundle


def build_pilot_console_snapshot(
    records: Sequence[Mapping[str, Any]],
    *,
    principal_id: str,
    as_of: str,
) -> dict[str, Any]:
    return build_snapshot(
        build_pilot_console_bundle(records),
        principal_id=principal_id,
        as_of=as_of,
    )


def _real_public_artifacts() -> tuple[dict[str, Any], ...]:
    return (
        {
            "artifact_type": "issue",
            "repository": PUBLIC_REPOSITORY,
            "public": True,
            "source_id": "issue:123",
            "revision_id": "open:2026-08-24T00:23:26Z",
            "observed_at": "2026-08-24T00:23:26Z",
            "effective_at": "2026-08-23T23:50:09Z",
            "raw_ref": "https://github.com/bitmaster162/continuityos/issues/123",
            "payload": {
                "number": 123,
                "title": "P2: Company Twin / Organizational Memory Foundation",
                "state": "open",
                "created_at": "2026-08-23T23:50:09Z",
                "updated_at": "2026-08-24T00:23:26Z",
            },
        },
        {
            "artifact_type": "pull_request",
            "repository": PUBLIC_REPOSITORY,
            "public": True,
            "source_id": "pr:124",
            "revision_id": "merged:72f3811c8bdd9def7b29c79dad4f2172f462af9d",
            "observed_at": "2026-08-24T00:22:58Z",
            "effective_at": "2026-08-24T00:22:57Z",
            "raw_ref": "https://github.com/bitmaster162/continuityos/pull/124",
            "payload": {
                "number": 124,
                "title": "P2A: synthetic 12-month Company Twin foundation",
                "state": "closed",
                "merged": True,
                "created_at": "2026-08-24T00:08:09Z",
                "merged_at": "2026-08-24T00:22:57Z",
                "head_sha": "e9d879cff9d1caf3e667e9043221e68c5b72511d",
                "base_sha": "9adb8ecc82f91adeb00c4f1af2d386954f49477a",
                "merge_commit_sha": "72f3811c8bdd9def7b29c79dad4f2172f462af9d",
            },
        },
        {
            "artifact_type": "commit",
            "repository": PUBLIC_REPOSITORY,
            "public": True,
            "source_id": "commit:72f3811c8bdd9def7b29c79dad4f2172f462af9d",
            "revision_id": "72f3811c8bdd9def7b29c79dad4f2172f462af9d",
            "observed_at": "2026-08-24T00:22:57Z",
            "effective_at": "2026-08-24T00:22:57Z",
            "raw_ref": "https://github.com/bitmaster162/continuityos/commit/72f3811c8bdd9def7b29c79dad4f2172f462af9d",
            "payload": {
                "sha": "72f3811c8bdd9def7b29c79dad4f2172f462af9d",
                "message": "P2A: synthetic 12-month Company Twin foundation (#124)",
                "committed_at": "2026-08-24T00:22:57Z",
                "pull_request_number": 124,
            },
        },
        {
            "artifact_type": "pull_request",
            "repository": PUBLIC_REPOSITORY,
            "public": True,
            "source_id": "pr:128",
            "revision_id": "merged:a3bcc6088a3727d087efa50e9cc0e7e96fcd2b5a",
            "observed_at": "2026-08-24T01:23:51Z",
            "effective_at": "2026-08-24T01:23:50Z",
            "raw_ref": "https://github.com/bitmaster162/continuityos/pull/128",
            "payload": {
                "number": 128,
                "title": "P2C: Company Twin Director/Worker/Agent policy plane",
                "state": "closed",
                "merged": True,
                "created_at": "2026-08-24T01:06:45Z",
                "merged_at": "2026-08-24T01:23:50Z",
                "head_sha": "b369b58cec768b5e19d5de771d01c3fd7b530f80",
                "base_sha": "16531eabeddf36e45e98340d636199bf6265c58e",
                "merge_commit_sha": "a3bcc6088a3727d087efa50e9cc0e7e96fcd2b5a",
            },
        },
        {
            "artifact_type": "commit",
            "repository": PUBLIC_REPOSITORY,
            "public": True,
            "source_id": "commit:a3bcc6088a3727d087efa50e9cc0e7e96fcd2b5a",
            "revision_id": "a3bcc6088a3727d087efa50e9cc0e7e96fcd2b5a",
            "observed_at": "2026-08-24T01:23:50Z",
            "effective_at": "2026-08-24T01:23:50Z",
            "raw_ref": "https://github.com/bitmaster162/continuityos/commit/a3bcc6088a3727d087efa50e9cc0e7e96fcd2b5a",
            "payload": {
                "sha": "a3bcc6088a3727d087efa50e9cc0e7e96fcd2b5a",
                "message": "P2C: Company Twin Director/Worker/Agent policy plane (#128)",
                "committed_at": "2026-08-24T01:23:50Z",
                "pull_request_number": 128,
            },
        },
        {
            "artifact_type": "workflow_run",
            "repository": PUBLIC_REPOSITORY,
            "public": True,
            "source_id": "workflow:32681056154",
            "revision_id": "run:32681056154:attempt:1",
            "observed_at": "2026-08-24T01:54:06Z",
            "effective_at": "2026-08-24T01:54:06Z",
            "raw_ref": "https://github.com/bitmaster162/continuityos/actions/runs/32681056154",
            "payload": {
                "run_id": 32681056154,
                "name": "review-gates",
                "run_number": 895,
                "status": "completed",
                "conclusion": "failure",
                "head_sha": "d85c95d6d3ad964fa66d9d768a17b3677a7b4e60",
                "created_at": "2026-08-24T01:50:11Z",
                "completed_at": "2026-08-24T01:54:06Z",
                "display_title": "P2D: Company Twin Operating Console",
                "failing_steps": [
                    "ubuntu / Python 3.11: Test clean source without installed package metadata",
                    "windows / Python 3.11: Test clean source without installed package metadata",
                ],
            },
        },
        {
            "artifact_type": "workflow_run",
            "repository": PUBLIC_REPOSITORY,
            "public": True,
            "source_id": "workflow:32681315315",
            "revision_id": "run:32681315315:attempt:1",
            "observed_at": "2026-08-24T02:07:48Z",
            "effective_at": "2026-08-24T02:07:48Z",
            "raw_ref": "https://github.com/bitmaster162/continuityos/actions/runs/32681315315",
            "payload": {
                "run_id": 32681315315,
                "name": "review-gates",
                "run_number": 897,
                "status": "completed",
                "conclusion": "success",
                "head_sha": "8df3c0d69fbea3cde1e532d0ea77a4407559cdac",
                "created_at": "2026-08-24T01:55:05Z",
                "completed_at": "2026-08-24T02:07:48Z",
                "display_title": "P2D: Company Twin Operating Console",
                "failing_steps": [],
            },
        },
        {
            "artifact_type": "pull_request",
            "repository": PUBLIC_REPOSITORY,
            "public": True,
            "source_id": "pr:132",
            "revision_id": "merged:0429ea2ea836b0fcbcc390ebecb4d7e8fc02ed05",
            "observed_at": "2026-08-24T02:48:19Z",
            "effective_at": "2026-08-24T02:48:19Z",
            "raw_ref": "https://github.com/bitmaster162/continuityos/pull/132",
            "payload": {
                "number": 132,
                "title": "P2D: Company Twin Operating Console",
                "state": "closed",
                "merged": True,
                "created_at": "2026-08-24T01:50:08Z",
                "merged_at": "2026-08-24T02:48:19Z",
                "head_sha": "8df3c0d69fbea3cde1e532d0ea77a4407559cdac",
                "base_sha": "a3bcc6088a3727d087efa50e9cc0e7e96fcd2b5a",
                "merge_commit_sha": "0429ea2ea836b0fcbcc390ebecb4d7e8fc02ed05",
            },
        },
        {
            "artifact_type": "commit",
            "repository": PUBLIC_REPOSITORY,
            "public": True,
            "source_id": "commit:0429ea2ea836b0fcbcc390ebecb4d7e8fc02ed05",
            "revision_id": "0429ea2ea836b0fcbcc390ebecb4d7e8fc02ed05",
            "observed_at": "2026-08-24T02:48:19Z",
            "effective_at": "2026-08-24T02:48:19Z",
            "raw_ref": "https://github.com/bitmaster162/continuityos/commit/0429ea2ea836b0fcbcc390ebecb4d7e8fc02ed05",
            "payload": {
                "sha": "0429ea2ea836b0fcbcc390ebecb4d7e8fc02ed05",
                "message": "P2D: Company Twin Operating Console (#132)",
                "committed_at": "2026-08-24T02:48:19Z",
                "pull_request_number": 132,
            },
        },
    )


REAL_PUBLIC_ARTIFACTS = _real_public_artifacts()


def public_fixture_document() -> dict[str, Any]:
    return {
        "schema_version": PILOT_SCHEMA_VERSION,
        "repository": PUBLIC_REPOSITORY,
        "public": True,
        "source_boundary": "PUBLIC_GITHUB_ONLY",
        "artifacts": copy.deepcopy(list(REAL_PUBLIC_ARTIFACTS)),
    }


def load_source_fixture(path: str | Path) -> dict[str, Any]:
    import json

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema_version") != PILOT_SCHEMA_VERSION:
        raise PublicGitHubPilotError("unsupported pilot fixture schema")
    if payload.get("repository") != PUBLIC_REPOSITORY or payload.get("public") is not True:
        raise PublicGitHubPilotError("source fixture boundary mismatch")
    if payload.get("source_boundary") != "PUBLIC_GITHUB_ONLY":
        raise PublicGitHubPilotError("source fixture boundary mismatch")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise PublicGitHubPilotError("source fixture artifacts are required")
    sanitized = [sanitize_public_artifact(item) for item in artifacts]
    normalized = {
        "schema_version": PILOT_SCHEMA_VERSION,
        "repository": PUBLIC_REPOSITORY,
        "public": True,
        "source_boundary": "PUBLIC_GITHUB_ONLY",
        "artifacts": sanitized,
    }
    return normalized


def assert_no_network_connector_calls() -> None:
    text = inspect.getsource(__import__(__name__, fromlist=["*"]))
    forbidden = ("urlopen(", "requests.", "httpx.", "socket.", "subprocess.")
    if any(token in text for token in forbidden):
        raise AssertionError("P2E-R1 core must not perform live network connector calls")
