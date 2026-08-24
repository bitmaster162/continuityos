from __future__ import annotations

import argparse
import ipaddress
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .company_twin import RECORD_COLLECTIONS, replay, validate_dataset
from .company_twin_policy import ACTIONS, evaluate, plan_lifecycle, validate_policy

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8768
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
CONSOLE_SCHEMA = "company-twin-console-snapshot/1"
BUNDLE_SCHEMA = "company-twin-console-bundle/1"


class CompanyTwinConsoleError(ValueError):
    pass


@dataclass(frozen=True)
class CompanyTwinConsoleConfig:
    bundle_path: Path | None = None


def _is_loopback_host(host: str) -> bool:
    value = host.strip().lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _validate_bind(host: str) -> None:
    if not _is_loopback_host(host):
        raise CompanyTwinConsoleError("Company Twin Console refuses non-loopback bind")


def _parse_iso(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except (TypeError, ValueError) as exc:
        raise CompanyTwinConsoleError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise CompanyTwinConsoleError("timestamp requires timezone")
    return parsed.astimezone(timezone.utc)


def _actor_by_principal(policy: Mapping[str, Any], principal_id: str) -> Mapping[str, Any] | None:
    for actor in policy.get("actors", []):
        if actor.get("principal_id") == principal_id:
            return actor
    return None


def _actor_by_id(policy: Mapping[str, Any], actor_id: str) -> Mapping[str, Any] | None:
    for actor in policy.get("actors", []):
        if actor.get("id") == actor_id:
            return actor
    return None


def _classification(record: Mapping[str, Any]) -> str:
    explicit = record.get("classification")
    if isinstance(explicit, str) and explicit:
        return explicit
    scope = str(record.get("scope", ""))
    if scope.startswith("restricted:"):
        return "RESTRICTED"
    return "INTERNAL"


def _resource(policy: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    scope = str(record.get("scope", ""))
    return {
        "id": str(record.get("id", "UNKNOWN")),
        "tenant_id": str(record.get("tenant_id", policy["tenant_id"])),
        "scope": scope,
        "source_acl_scopes": [scope] if scope else [],
        "classification": _classification(record),
        "team_id": scope.removeprefix("team:") if scope.startswith("team:") else None,
        "legal_hold": record.get("legal_hold") is True,
    }


def _purpose(actor: Mapping[str, Any], record: Mapping[str, Any]) -> str:
    scope = str(record.get("scope", ""))
    if scope.startswith("restricted:finance"):
        return "finance"
    role = str(actor.get("role", ""))
    if role == "DIRECTOR":
        return "governance"
    if role == "AGENT":
        return "research"
    scopes = set(actor.get("scopes", []))
    if "team:engineering" in scopes:
        return "engineering"
    if "team:operations" in scopes:
        return "operations"
    return "audit"


def _filter_collection(
    policy: Mapping[str, Any],
    principal_id: str,
    actor: Mapping[str, Any],
    records: list[dict[str, Any]],
    *,
    at: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    visible: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    for record in records:
        receipt = evaluate(
            policy,
            principal_id=principal_id,
            resource=_resource(policy, record),
            action="READ",
            context={"purpose": _purpose(actor, record)},
            at=at,
        )
        if receipt["decision"] == "ALLOW":
            visible.append(dict(record))
            receipts.append(receipt)
    return visible, receipts


def _visible_ids(snapshot: Mapping[str, Any]) -> set[str]:
    return {
        str(record["id"])
        for collection in RECORD_COLLECTIONS
        for record in snapshot.get(collection, [])
    }


def _prune_references(snapshot: dict[str, Any]) -> None:
    visible = _visible_ids(snapshot)
    snapshot["relationships"] = [
        record
        for record in snapshot["relationships"]
        if record.get("from_entity_id") in visible and record.get("to_entity_id") in visible
    ]
    visible = _visible_ids(snapshot)
    snapshot["events"] = [
        record
        for record in snapshot["events"]
        if set(record.get("evidence_ids", [])).issubset(visible)
        and set(record.get("entity_ids", [])).issubset(visible)
    ]
    visible = _visible_ids(snapshot)
    snapshot["decisions"] = [
        record
        for record in snapshot["decisions"]
        if set(record.get("evidence_ids", [])).issubset(visible)
        and (record.get("supersedes") is None or record.get("supersedes") in visible)
    ]
    visible = _visible_ids(snapshot)
    snapshot["outcomes"] = [
        record
        for record in snapshot["outcomes"]
        if record.get("decision_id") in visible
        and set(record.get("evidence_ids", [])).issubset(visible)
    ]
    visible = _visible_ids(snapshot)
    snapshot["process_observations"] = [
        record
        for record in snapshot["process_observations"]
        if set(record.get("evidence_ids", [])).issubset(visible)
    ]
    visible = _visible_ids(snapshot)
    snapshot["inferences"] = [
        record
        for record in snapshot["inferences"]
        if set(record.get("evidence_ids", [])).issubset(visible)
        and set(record.get("event_ids", [])).issubset(visible)
        and set(record.get("decision_ids", [])).issubset(visible)
    ]
    superseded = {
        str(record["supersedes"])
        for record in snapshot["decisions"]
        if record.get("supersedes") is not None
    }
    for record in snapshot["decisions"]:
        record["replay_status"] = "SUPERSEDED" if record["id"] in superseded else "ACTIVE"


def _decision_lineages(snapshot: Mapping[str, Any]) -> dict[str, list[str]]:
    decisions = {str(record["id"]): record for record in snapshot.get("decisions", [])}
    result: dict[str, list[str]] = {}
    for decision_id, decision in decisions.items():
        lineage = [decision_id]
        current = decision
        seen = {decision_id}
        while current.get("supersedes") is not None:
            previous_id = str(current["supersedes"])
            if previous_id in seen or previous_id not in decisions:
                break
            lineage.append(previous_id)
            seen.add(previous_id)
            current = decisions[previous_id]
        result[decision_id] = lineage
    return result


def _record_time(record: Mapping[str, Any]) -> str:
    for key in (
        "occurred_at",
        "decided_at",
        "recorded_at",
        "observed_at",
        "effective_from",
        "created_at",
    ):
        value = record.get(key)
        if isinstance(value, str):
            return value
    return ""


def _timeline(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for collection in ("events", "decisions", "outcomes", "process_observations"):
        for record in snapshot.get(collection, []):
            items.append(
                {
                    "id": record["id"],
                    "kind": collection,
                    "time": _record_time(record),
                    "title": record.get("title", record.get("claim", "")),
                    "scope": record["scope"],
                    "truth_class": record["truth_class"],
                }
            )
    return sorted(items, key=lambda item: (item["time"], item["kind"], item["id"]))


def _organization_graph(policy: Mapping[str, Any], actor: Mapping[str, Any]) -> dict[str, Any]:
    actor_id = str(actor["id"])
    role = str(actor["role"])
    allowed_ids = {actor_id}
    if role == "DIRECTOR":
        allowed_ids.update(str(item["id"]) for item in policy.get("actors", []))
    else:
        manager_id = actor.get("manager_actor_id")
        if manager_id:
            allowed_ids.add(str(manager_id))
        for item in policy.get("actors", []):
            if item.get("manager_actor_id") == actor_id:
                allowed_ids.add(str(item["id"]))
        if role == "WORKER":
            for item in policy.get("actors", []):
                if item.get("role") == "DIRECTOR":
                    allowed_ids.add(str(item["id"]))

    nodes = [
        {
            "id": item["id"],
            "name": item.get("name", item["id"]),
            "actor_kind": item["actor_kind"],
            "role": item["role"],
        }
        for item in policy.get("actors", [])
        if str(item["id"]) in allowed_ids
    ]
    edges = []
    for item in policy.get("actors", []):
        iid = str(item["id"])
        manager_id = item.get("manager_actor_id")
        if manager_id and iid in allowed_ids and str(manager_id) in allowed_ids:
            edges.append({"from": str(manager_id), "to": iid, "relation": "MANAGES"})
    return {"nodes": nodes, "edges": edges}


def _capability_scope(actor: Mapping[str, Any]) -> str:
    role = str(actor.get("role", ""))
    scopes = [str(scope) for scope in actor.get("scopes", [])]
    if role == "DIRECTOR":
        return "company"
    for scope in scopes:
        if scope.startswith("team:"):
            return scope
    return scopes[0] if scopes else "company"


def _capabilities(
    policy: Mapping[str, Any],
    principal_id: str,
    actor: Mapping[str, Any],
    *,
    at: str,
) -> dict[str, Any]:
    scope = _capability_scope(actor)
    representative = {
        "id": "console:capability-probe",
        "tenant_id": policy["tenant_id"],
        "scope": scope,
        "source_acl_scopes": [scope],
        "classification": "INTERNAL",
        "team_id": scope.removeprefix("team:") if scope.startswith("team:") else None,
    }
    purpose = _purpose(actor, representative)
    result: dict[str, Any] = {}
    for action in sorted(ACTIONS):
        receipt = evaluate(
            policy,
            principal_id=principal_id,
            resource=representative,
            action=action,
            context={"purpose": purpose},
            at=at,
        )
        result[action] = {
            "allowed": receipt["decision"] == "ALLOW",
            "reason": receipt["reason"],
            "receipt_sha256": receipt["receipt_sha256"],
        }
    result["EXECUTE"] = {
        "allowed": False,
        "reason": "NOT_IN_P2C_POLICY_ACTIONS",
        "receipt_sha256": None,
    }
    return result


def _delegations(policy: Mapping[str, Any], actor: Mapping[str, Any]) -> list[dict[str, Any]]:
    actor_id = str(actor["id"])
    role = str(actor["role"])
    result = []
    for delegation in policy.get("delegations", []):
        if role == "DIRECTOR" or delegation.get("grantee_actor_id") == actor_id or delegation.get("grantor_actor_id") == actor_id:
            result.append(
                {
                    "id": delegation["id"],
                    "grantor_actor_id": delegation["grantor_actor_id"],
                    "grantee_actor_id": delegation["grantee_actor_id"],
                    "actions": list(delegation.get("actions", [])),
                    "scopes": list(delegation.get("scopes", [])),
                    "expires_at": delegation.get("expires_at"),
                    "parent_id": delegation.get("parent_id"),
                }
            )
    return sorted(result, key=lambda item: item["id"])


def _proposal_view(
    bundle: Mapping[str, Any],
    policy: Mapping[str, Any],
    principal_id: str,
    actor: Mapping[str, Any],
    *,
    at: str,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    at_dt = _parse_iso(at)
    for proposal in bundle.get("proposals", []):
        if _parse_iso(str(proposal["created_at"])) > at_dt:
            continue
        resource = _resource(policy, proposal)
        receipt = evaluate(
            policy,
            principal_id=principal_id,
            resource=resource,
            action="READ",
            context={"purpose": _purpose(actor, proposal)},
            at=at,
        )
        if receipt["decision"] != "ALLOW":
            continue
        result.append(
            {
                "id": proposal["id"],
                "actor_principal_id": proposal["actor_principal_id"],
                "scope": proposal["scope"],
                "created_at": proposal["created_at"],
                "status": proposal["status"],
                "summary": proposal["summary"],
            }
        )
    return sorted(result, key=lambda item: (item["created_at"], item["id"]))


def _lifecycle_previews(
    policy: Mapping[str, Any],
    principal_id: str,
    actor: Mapping[str, Any],
    *,
    at: str,
) -> list[dict[str, Any]]:
    if actor.get("role") != "DIRECTOR":
        return []
    resource = {
        "id": "console:company-memory",
        "tenant_id": policy["tenant_id"],
        "scope": "company",
        "source_acl_scopes": ["company"],
        "classification": "INTERNAL",
        "legal_hold": False,
    }
    return [
        plan_lifecycle(
            policy,
            principal_id=principal_id,
            resource=resource,
            operation=operation,
            context={"purpose": "governance"},
            at=at,
        )
        for operation in ("EXPORT", "DELETE", "LEGAL_HOLD")
    ]


def validate_bundle(bundle: Mapping[str, Any]) -> None:
    if bundle.get("schema_version") != BUNDLE_SCHEMA:
        raise CompanyTwinConsoleError("unsupported console bundle schema")
    memory = bundle.get("memory")
    policy = bundle.get("policy")
    if not isinstance(memory, Mapping) or not isinstance(policy, Mapping):
        raise CompanyTwinConsoleError("bundle requires memory and policy objects")
    validate_dataset(memory)
    validate_policy(policy)
    memory_principals = {str(item["id"]) for item in memory["principals"]}
    policy_principals = {str(item["principal_id"]) for item in policy["actors"]}
    if memory_principals != policy_principals:
        raise CompanyTwinConsoleError("memory principals must match policy principal bindings")
    for proposal in bundle.get("proposals", []):
        required = {"id", "actor_principal_id", "scope", "created_at", "status", "summary"}
        if not required.issubset(proposal):
            raise CompanyTwinConsoleError("proposal missing required fields")
        if proposal["actor_principal_id"] not in policy_principals:
            raise CompanyTwinConsoleError("proposal references unknown principal")
        _parse_iso(str(proposal["created_at"]))
    runtime = bundle.get("runtime")
    if runtime is not None:
        if not isinstance(runtime, Mapping) or runtime.get("read_only") is not True:
            raise CompanyTwinConsoleError("runtime summary must be read-only")


def load_bundle(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise CompanyTwinConsoleError("console bundle must be a JSON object")
    if "policy_ref" in payload and "policy" not in payload:
        policy_path = (source.parent / str(payload["policy_ref"])).resolve()
        payload["policy"] = json.loads(policy_path.read_text(encoding="utf-8"))
    validate_bundle(payload)
    return payload


def build_snapshot(
    bundle: Mapping[str, Any],
    *,
    principal_id: str,
    as_of: str,
) -> dict[str, Any]:
    validate_bundle(bundle)
    memory = bundle["memory"]
    policy = bundle["policy"]
    actor = _actor_by_principal(policy, principal_id)
    if actor is None:
        raise CompanyTwinConsoleError("snapshot unavailable")

    raw = replay(memory, principal_id=principal_id, as_of=as_of)
    filtered = deepcopy(raw)
    receipts: list[dict[str, Any]] = []
    for collection in RECORD_COLLECTIONS:
        visible, collection_receipts = _filter_collection(
            policy,
            principal_id,
            actor,
            list(raw[collection]),
            at=as_of,
        )
        filtered[collection] = visible
        receipts.extend(collection_receipts)
    _prune_references(filtered)

    surviving_ids = _visible_ids(filtered)
    receipts = [receipt for receipt in receipts if receipt["resource_ref"] in surviving_ids]

    manager = None
    manager_id = actor.get("manager_actor_id")
    if manager_id:
        manager_actor = _actor_by_id(policy, str(manager_id))
        if manager_actor is not None:
            manager = {
                "id": manager_actor["id"],
                "name": manager_actor.get("name", manager_actor["id"]),
                "role": manager_actor["role"],
            }

    return {
        "schema_version": CONSOLE_SCHEMA,
        "read_only": True,
        "organization": dict(memory["organization"]),
        "as_of": raw["as_of"],
        "principal_id": principal_id,
        "actor": {
            "id": actor["id"],
            "name": actor.get("name", actor["id"]),
            "actor_kind": actor["actor_kind"],
            "role": actor["role"],
            "manager": manager,
        },
        "runtime": dict(bundle.get("runtime", {
            "read_only": True,
            "twin_baseline": "R21H",
            "mode": "LOCAL_SHADOW",
            "execution_authority": "NONE",
            "can_execute": False,
        })),
        "governance": {
            "execution_authority": "NONE",
            "can_execute": False,
            "can_trade": False,
            "capital_permission": "DENY",
        },
        "capabilities": _capabilities(policy, principal_id, actor, at=as_of),
        "delegations": _delegations(policy, actor),
        "organization_graph": _organization_graph(policy, actor),
        "counts": {collection: len(filtered[collection]) for collection in RECORD_COLLECTIONS},
        "timeline": _timeline(filtered),
        "decisions": filtered["decisions"],
        "decision_lineages": _decision_lineages(filtered),
        "evidence": filtered["evidence"],
        "events": filtered["events"],
        "outcomes": filtered["outcomes"],
        "relationships": filtered["relationships"],
        "process_observations": filtered["process_observations"],
        "inferences": filtered["inferences"],
        "proposals": _proposal_view(bundle, policy, principal_id, actor, at=as_of),
        "policy_receipts": sorted(receipts, key=lambda item: item["resource_ref"]),
        "lifecycle_previews": _lifecycle_previews(policy, principal_id, actor, at=as_of),
    }


def _demo_memory() -> dict[str, Any]:
    principals = [
        {"id": "principal_director", "name": "ContinuityOS Director", "role": "DIRECTOR", "scopes": ["company", "team:engineering", "team:operations", "restricted:finance"]},
        {"id": "principal_eng_worker", "name": "Engineering Worker", "role": "WORKER", "scopes": ["company", "team:engineering"]},
        {"id": "principal_ops_worker", "name": "Operations Worker", "role": "WORKER", "scopes": ["company", "team:operations"]},
        {"id": "principal_research_robot", "name": "Research Robot", "role": "AGENT", "scopes": ["company", "team:engineering"]},
    ]
    return {
        "schema_version": "company-twin-p2a/1",
        "organization": {"id": "org_continuityos_lab", "name": "ContinuityOS Lab", "industry": "AI infrastructure", "synthetic": True},
        "period": {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"},
        "source_authorities": [
            {"id": "auth_drive", "name": "Synthetic Drive", "authority": "SOURCE"},
            {"id": "auth_slack", "name": "Synthetic Slack", "authority": "SOURCE"},
            {"id": "auth_github", "name": "Synthetic GitHub", "authority": "SOURCE"},
            {"id": "auth_finance", "name": "Synthetic Finance", "authority": "RESTRICTED_SOURCE"},
        ],
        "principals": principals,
        "entities": [
            {"id": "ent_company", "type": "organization", "name": "ContinuityOS Lab", "created_at": "2026-01-01T00:00:00Z", "scope": "company", "truth_class": "FACT"},
            {"id": "ent_eng", "type": "team", "name": "Engineering", "created_at": "2026-01-01T00:00:00Z", "scope": "team:engineering", "truth_class": "FACT"},
            {"id": "ent_ops", "type": "team", "name": "Operations", "created_at": "2026-01-01T00:00:00Z", "scope": "team:operations", "truth_class": "FACT"},
            {"id": "ent_fin", "type": "financial_plan", "name": "Runway Plan", "created_at": "2026-01-01T00:00:00Z", "scope": "restricted:finance", "truth_class": "FACT"},
        ],
        "relationships": [
            {"id": "rel_eng_company", "from_entity_id": "ent_eng", "to_entity_id": "ent_company", "relation": "PART_OF", "effective_from": "2026-01-01T00:00:00Z", "scope": "team:engineering", "truth_class": "FACT"},
            {"id": "rel_ops_company", "from_entity_id": "ent_ops", "to_entity_id": "ent_company", "relation": "PART_OF", "effective_from": "2026-01-01T00:00:00Z", "scope": "team:operations", "truth_class": "FACT"},
            {"id": "rel_fin_company", "from_entity_id": "ent_fin", "to_entity_id": "ent_company", "relation": "GOVERNS_BUDGET", "effective_from": "2026-01-01T00:00:00Z", "scope": "restricted:finance", "truth_class": "FACT"},
        ],
        "evidence": [
            {"id": "ev_plan_r1", "kind": "document", "title": "2026 operating plan r1", "recorded_at": "2026-01-10T10:05:00Z", "scope": "company", "truth_class": "EVIDENCE", "source_authority_id": "auth_drive", "source_ref": "synthetic://drive/strategy?r=1"},
            {"id": "ev_finance", "kind": "financial", "title": "Runway 12 months", "recorded_at": "2026-02-01T08:05:00Z", "scope": "restricted:finance", "truth_class": "EVIDENCE", "source_authority_id": "auth_finance", "source_ref": "synthetic://drive/finance?r=1"},
            {"id": "ev_replay_fix", "kind": "message", "title": "Replay regression fixed", "recorded_at": "2026-02-12T12:02:00Z", "scope": "team:engineering", "truth_class": "EVIDENCE", "source_authority_id": "auth_slack", "source_ref": "synthetic://slack/eng-thread-41?r=1"},
            {"id": "ev_plan_r2", "kind": "document", "title": "2026 operating plan r2", "recorded_at": "2026-03-15T09:10:00Z", "scope": "company", "truth_class": "EVIDENCE", "source_authority_id": "auth_drive", "source_ref": "synthetic://drive/strategy?r=2"},
            {"id": "ev_robot_prop", "kind": "message", "title": "Research robot provenance proposal", "recorded_at": "2026-05-20T16:05:00Z", "scope": "team:engineering", "truth_class": "EVIDENCE", "source_authority_id": "auth_slack", "source_ref": "synthetic://slack/agent-proposal-7?r=1"},
            {"id": "ev_p2a", "kind": "pull_request", "title": "P2A merged", "recorded_at": "2026-08-24T00:22:57Z", "scope": "company", "truth_class": "EVIDENCE", "source_authority_id": "auth_github", "source_ref": "synthetic://github/pulls/124"},
            {"id": "ev_p2c", "kind": "pull_request", "title": "P2C policy plane merged", "recorded_at": "2026-08-24T01:23:50Z", "scope": "company", "truth_class": "EVIDENCE", "source_authority_id": "auth_github", "source_ref": "synthetic://github/pulls/128"},
            {"id": "ev_ops", "kind": "message", "title": "Operations review complete", "recorded_at": "2026-08-24T01:30:00Z", "scope": "team:operations", "truth_class": "EVIDENCE", "source_authority_id": "auth_slack", "source_ref": "synthetic://slack/ops-review"},
            {"id": "ev_eng_secret", "kind": "document", "title": "Confidential engineering note", "recorded_at": "2026-08-24T01:31:00Z", "scope": "team:engineering", "truth_class": "EVIDENCE", "classification": "CONFIDENTIAL", "source_authority_id": "auth_drive", "source_ref": "synthetic://drive/eng-secret"},
            {"id": "ev_other_tenant", "kind": "document", "title": "Other tenant secret", "recorded_at": "2026-08-24T01:32:00Z", "scope": "company", "tenant_id": "tenant_other", "truth_class": "EVIDENCE", "source_authority_id": "auth_drive", "source_ref": "synthetic://other-tenant/secret"},
        ],
        "events": [
            {"id": "evt_replay_fix", "title": "Replay regression fixed", "occurred_at": "2026-02-12T12:05:00Z", "scope": "team:engineering", "truth_class": "FACT", "entity_ids": ["ent_eng"], "evidence_ids": ["ev_replay_fix"]},
            {"id": "evt_robot_prop", "title": "Research robot submitted provenance proposal", "occurred_at": "2026-05-20T16:10:00Z", "scope": "team:engineering", "truth_class": "FACT", "entity_ids": ["ent_eng"], "evidence_ids": ["ev_robot_prop"]},
            {"id": "evt_p2c", "title": "P2C policy plane merged", "occurred_at": "2026-08-24T01:23:50Z", "scope": "company", "truth_class": "FACT", "entity_ids": ["ent_company"], "evidence_ids": ["ev_p2c"]},
            {"id": "evt_ops", "title": "Operations review complete", "occurred_at": "2026-08-24T01:30:00Z", "scope": "team:operations", "truth_class": "FACT", "entity_ids": ["ent_ops"], "evidence_ids": ["ev_ops"]},
        ],
        "decisions": [
            {"id": "dec_localfirst", "title": "Keep ContinuityOS local-first", "decided_at": "2026-01-10T10:10:00Z", "scope": "company", "truth_class": "FACT", "rationale": "Preserve custody and governance.", "evidence_ids": ["ev_plan_r1"], "supersedes": None},
            {"id": "dec_company_twin", "title": "Add Company Twin product line", "decided_at": "2026-03-15T09:20:00Z", "scope": "company", "truth_class": "FACT", "rationale": "Extend continuity from person to organization.", "evidence_ids": ["ev_plan_r2"], "supersedes": "dec_localfirst"},
            {"id": "dec_robot_research", "title": "Allow managed research robot to read/propose", "decided_at": "2026-05-20T16:20:00Z", "scope": "team:engineering", "truth_class": "FACT", "rationale": "Prepare bounded robot workforce without execution authority.", "evidence_ids": ["ev_robot_prop"], "supersedes": None},
            {"id": "dec_finance_guard", "title": "Keep finance restricted", "decided_at": "2026-02-01T08:10:00Z", "scope": "restricted:finance", "truth_class": "FACT", "rationale": "Finance remains restricted by source ACL.", "evidence_ids": ["ev_finance"], "supersedes": None},
            {"id": "dec_policy_plane", "title": "Adopt Director/Worker/Agent policy plane", "decided_at": "2026-08-24T01:23:50Z", "scope": "company", "truth_class": "FACT", "rationale": "Govern human and managed-agent access under one policy graph.", "evidence_ids": ["ev_p2c"], "supersedes": "dec_company_twin"},
        ],
        "outcomes": [
            {"id": "out_company_twin", "title": "P2A Company Twin foundation merged", "occurred_at": "2026-08-24T00:22:57Z", "scope": "company", "truth_class": "FACT", "decision_id": "dec_company_twin", "evidence_ids": ["ev_p2a"]},
            {"id": "out_policy", "title": "P2C policy qualification passed", "occurred_at": "2026-08-24T01:23:50Z", "scope": "company", "truth_class": "FACT", "decision_id": "dec_policy_plane", "evidence_ids": ["ev_p2c"]},
        ],
        "process_observations": [
            {"id": "proc_replay", "title": "Replay regression checks precede merge", "observed_at": "2026-02-13T12:00:00Z", "scope": "team:engineering", "truth_class": "FACT", "evidence_ids": ["ev_replay_fix"]},
            {"id": "proc_ops", "title": "Operations reviews preserve read-only gates", "observed_at": "2026-08-24T01:31:00Z", "scope": "team:operations", "truth_class": "FACT", "evidence_ids": ["ev_ops"]},
        ],
        "inferences": [
            {"id": "inf_robot", "claim": "Managed robots can add research capacity without inheriting human execution authority.", "created_at": "2026-05-21T12:00:00Z", "scope": "team:engineering", "truth_class": "INFERENCE", "confidence": 0.84, "evidence_ids": ["ev_robot_prop"], "event_ids": ["evt_robot_prop"], "decision_ids": ["dec_robot_research"]},
        ],
    }


def _demo_policy() -> dict[str, Any]:
    return {
        "schema_version": "company-twin-p2c/1",
        "tenant_id": "tenant_continuityos_lab",
        "max_delegation_depth": 3,
        "revoked_delegation_ids": [],
        "actors": [
            {"actor_kind": "HUMAN", "id": "actor_director", "name": "ContinuityOS Director", "principal_id": "principal_director", "role": "DIRECTOR", "scopes": ["company", "team:engineering", "team:operations", "restricted:finance"]},
            {"actor_kind": "HUMAN", "id": "actor_eng", "name": "Engineering Worker", "principal_id": "principal_eng_worker", "role": "WORKER", "scopes": ["company", "team:engineering"]},
            {"actor_kind": "HUMAN", "id": "actor_ops", "name": "Operations Worker", "principal_id": "principal_ops_worker", "role": "WORKER", "scopes": ["company", "team:operations"]},
            {"actor_kind": "AGENT", "id": "actor_robot", "manager_actor_id": "actor_eng", "name": "Research Robot", "principal_id": "principal_research_robot", "role": "AGENT", "scopes": ["team:engineering"]},
        ],
        "grants": [
            {"actions": ["READ", "PROPOSE", "APPROVE", "DELEGATE", "REVOKE", "EXPORT", "DELETE", "LEGAL_HOLD"], "actor_id": "actor_director", "classifications": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"], "id": "grant_director_company", "purposes": ["governance", "operations", "engineering", "research", "audit"], "scopes": ["company"]},
            {"actions": ["READ", "PROPOSE", "APPROVE", "DELEGATE", "REVOKE", "EXPORT", "DELETE", "LEGAL_HOLD"], "actor_id": "actor_director", "classifications": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"], "id": "grant_director_eng", "purposes": ["governance", "engineering", "research", "audit"], "scopes": ["team:engineering"]},
            {"actions": ["READ", "PROPOSE", "APPROVE", "DELEGATE", "REVOKE", "EXPORT", "DELETE", "LEGAL_HOLD"], "actor_id": "actor_director", "classifications": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"], "id": "grant_director_ops", "purposes": ["governance", "operations", "audit"], "scopes": ["team:operations"]},
            {"actions": ["READ", "EXPORT", "DELETE", "LEGAL_HOLD"], "actor_id": "actor_director", "classifications": ["CONFIDENTIAL", "RESTRICTED"], "id": "grant_director_fin", "purposes": ["governance", "finance", "audit"], "scopes": ["restricted:finance"]},
            {"actions": ["READ", "PROPOSE"], "actor_id": "actor_eng", "classifications": ["PUBLIC", "INTERNAL"], "id": "grant_eng_company", "purposes": ["engineering", "research"], "scopes": ["company"]},
            {"actions": ["READ", "PROPOSE"], "actor_id": "actor_eng", "classifications": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"], "id": "grant_eng_team", "purposes": ["engineering", "research"], "scopes": ["team:engineering"]},
            {"actions": ["READ", "PROPOSE"], "actor_id": "actor_ops", "classifications": ["PUBLIC", "INTERNAL"], "id": "grant_ops_company", "purposes": ["operations"], "scopes": ["company"]},
            {"actions": ["READ", "PROPOSE"], "actor_id": "actor_ops", "classifications": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"], "id": "grant_ops_team", "purposes": ["operations"], "scopes": ["team:operations"]},
        ],
        "delegations": [
            {"actions": ["READ", "PROPOSE"], "classifications": ["PUBLIC", "INTERNAL"], "expires_at": "2026-12-31T23:59:59Z", "grantee_actor_id": "actor_robot", "grantor_actor_id": "actor_director", "id": "deleg_director_robot_eng", "purposes": ["research"], "scopes": ["team:engineering"]},
        ],
        "explicit_denies": [
            {"action": "READ", "actor_id": "actor_eng", "id": "deny_eng_fin", "scope": "restricted:finance"},
            {"action": "READ", "actor_id": "actor_ops", "id": "deny_ops_eng", "scope": "team:engineering"},
        ],
    }


def synthetic_demo_bundle() -> dict[str, Any]:
    bundle = {
        "schema_version": BUNDLE_SCHEMA,
        "memory": _demo_memory(),
        "policy": _demo_policy(),
        "runtime": {"read_only": True, "twin_baseline": "R21H", "mode": "LOCAL_SHADOW", "execution_authority": "NONE", "can_execute": False},
        "proposals": [
            {"id": "proposal_provenance_receipts", "actor_principal_id": "principal_research_robot", "scope": "team:engineering", "classification": "INTERNAL", "created_at": "2026-05-20T16:00:00Z", "status": "PENDING_HUMAN_REVIEW", "summary": "Add provenance receipts to Company Twin evidence flow."}
        ],
    }
    validate_bundle(bundle)
    return bundle


_UI = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Company Twin Operating Console</title>
<style>
body{margin:0;background:#0a0d12;color:#eef3f8;font:14px system-ui,sans-serif}.wrap{max-width:1100px;margin:auto;padding:24px}
header{display:flex;justify-content:space-between;gap:12px;align-items:center}.badge{border:1px solid #31563f;padding:5px 9px;border-radius:999px;color:#8ef0ad}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}.card{background:#111821;border:1px solid #263342;border-radius:12px;padding:14px}.wide{grid-column:span 2}
h1{margin:0}h2{font-size:13px;color:#93a4b7;text-transform:uppercase}.muted{color:#93a4b7}.row{padding:6px 0;border-top:1px solid #202b37}.row:first-child{border:0}
select,input,button{background:#131c27;color:#eef3f8;border:1px solid #34465a;border-radius:8px;padding:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:760px){.grid{grid-template-columns:1fr}.wide{grid-column:span 1}}
</style></head>
<body><div class="wrap">
<header><div><h1>Company Twin Operating Console</h1><div class="muted">Director · Workers · Managed Agents</div></div><span class="badge">READ ONLY</span></header>
<div style="margin-top:14px"><select id="principal">
<option value="principal_director">Director</option>
<option value="principal_eng_worker">Engineering Worker</option>
<option value="principal_ops_worker">Operations Worker</option>
<option value="principal_research_robot">Research Robot</option>
</select> <input id="asof" value="2026-08-24T01:30:00Z"> <button id="refresh">Refresh</button></div>
<div id="error" style="color:#ff8792;margin-top:10px"></div>
<div class="grid">
<section class="card"><h2>Actor</h2><div id="actor"></div></section>
<section class="card"><h2>Authority</h2><div id="authority"></div></section>
<section class="card"><h2>Visible memory</h2><div id="counts"></div></section>
<section class="card wide"><h2>Timeline</h2><div id="timeline"></div></section>
<section class="card"><h2>Managed organization</h2><div id="graph"></div></section>
<section class="card wide"><h2>Decisions</h2><div id="decisions"></div></section>
<section class="card"><h2>Agent proposals</h2><div id="proposals"></div></section>
</div></div>
<script>
const $=id=>document.getElementById(id);
const text=(id,value)=>{$(id).textContent=value};
async function refresh(){
  $("error").textContent="";
  const p=encodeURIComponent($("principal").value), a=encodeURIComponent($("asof").value);
  try{
    const r=await fetch(`/api/snapshot?principal=${p}&as_of=${a}`,{headers:{Accept:"application/json"}});
    const d=await r.json(); if(!r.ok) throw new Error(d.error||"request failed");
    text("actor",`${d.actor.name} · ${d.actor.role} · ${d.actor.actor_kind}`);
    text("authority",`execute=${d.governance.can_execute} · trade=${d.governance.can_trade} · capital=${d.governance.capital_permission}`);
    text("counts",Object.entries(d.counts).map(([k,v])=>`${k}: ${v}`).join(" · "));
    text("timeline",d.timeline.map(x=>`${x.time}  ${x.kind}  ${x.title}`).join("\n")||"No visible records");
    text("graph",d.organization_graph.nodes.map(x=>`${x.name} (${x.role})`).join("\n"));
    text("decisions",d.decisions.map(x=>`${x.replay_status||"ACTIVE"} · ${x.title}`).join("\n")||"No visible decisions");
    text("proposals",d.proposals.map(x=>`${x.status} · ${x.summary}`).join("\n")||"No visible proposals");
  }catch(e){$("error").textContent=String(e)}
}
$("refresh").addEventListener("click",refresh); refresh();
</script></body></html>"""


class _ConsoleHandler(BaseHTTPRequestHandler):
    server_version = "ContinuityOSCompanyTwinConsole/1"

    def _send_json(self, status: int, payload: Mapping[str, Any], *, head_only: bool = False) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _send_html(self, *, head_only: bool = False) -> None:
        body = _UI.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _handle_read(self, *, head_only: bool) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(head_only=head_only)
            return
        if parsed.path != "/api/snapshot":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"}, head_only=head_only)
            return
        query = parse_qs(parsed.query)
        principal = query.get("principal", [""])[0]
        as_of = query.get("as_of", [""])[0]
        if not principal or not as_of:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "principal and as_of are required"}, head_only=head_only)
            return
        try:
            payload = build_snapshot(self.server.console_bundle, principal_id=principal, as_of=as_of)  # type: ignore[attr-defined]
        except (CompanyTwinConsoleError, KeyError, ValueError):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "snapshot unavailable"}, head_only=head_only)
            return
        self._send_json(HTTPStatus.OK, payload, head_only=head_only)

    def do_GET(self) -> None:
        self._handle_read(head_only=False)

    def do_HEAD(self) -> None:
        self._handle_read(head_only=True)

    def _reject_write(self) -> None:
        self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "read-only console"})

    do_POST = _reject_write
    do_PUT = _reject_write
    do_PATCH = _reject_write
    do_DELETE = _reject_write

    def log_message(self, format: str, *args: object) -> None:
        return


class CompanyTwinConsoleServer(ThreadingHTTPServer):
    console_bundle: Mapping[str, Any]


def make_server(
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    bundle: Mapping[str, Any] | None = None,
    config: CompanyTwinConsoleConfig | None = None,
) -> CompanyTwinConsoleServer:
    _validate_bind(host)
    if bundle is not None and config is not None:
        raise CompanyTwinConsoleError("provide bundle or config, not both")
    if bundle is None:
        if config is not None and config.bundle_path is not None:
            bundle = load_bundle(config.bundle_path)
        else:
            bundle = synthetic_demo_bundle()
    validate_bundle(bundle)
    server = CompanyTwinConsoleServer((host, port), _ConsoleHandler)
    server.console_bundle = bundle
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ContinuityOS Company Twin Operating Console")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args(argv)
    config = CompanyTwinConsoleConfig(bundle_path=args.bundle)
    server = make_server(host=args.host, port=args.port, config=config)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
