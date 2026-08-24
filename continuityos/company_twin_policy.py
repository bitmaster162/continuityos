from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping

ACTIONS = {
    "READ",
    "PROPOSE",
    "APPROVE",
    "DELEGATE",
    "REVOKE",
    "EXPORT",
    "DELETE",
    "LEGAL_HOLD",
}
ROLES = {"DIRECTOR", "WORKER", "AGENT", "SERVICE"}
ACTOR_KINDS = {"HUMAN", "AGENT", "SERVICE"}
AGENT_ACTION_CEILING = {"READ", "PROPOSE"}
ROLE_ACTION_CEILINGS = {
    "DIRECTOR": set(ACTIONS),
    "WORKER": {"READ", "PROPOSE"},
    "AGENT": set(AGENT_ACTION_CEILING),
    "SERVICE": {"READ"},
}
LIFECYCLE_OPERATIONS = {"EXPORT", "DELETE", "RETENTION_PURGE", "LEGAL_HOLD"}


class CompanyTwinPolicyError(ValueError):
    pass


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise CompanyTwinPolicyError("timestamp must be a non-empty string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CompanyTwinPolicyError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise CompanyTwinPolicyError(f"timestamp must include timezone: {value}")
    return parsed.astimezone(timezone.utc)


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _actor_by_id(policy: Mapping[str, Any], actor_id: str) -> Mapping[str, Any] | None:
    for actor in policy.get("actors", []):
        if actor.get("id") == actor_id:
            return actor
    return None


def _actor_by_principal(policy: Mapping[str, Any], principal_id: str) -> Mapping[str, Any] | None:
    for actor in policy.get("actors", []):
        if actor.get("principal_id") == principal_id:
            return actor
    return None


def _delegation_by_id(policy: Mapping[str, Any], delegation_id: str) -> Mapping[str, Any] | None:
    for delegation in policy.get("delegations", []):
        if delegation.get("id") == delegation_id:
            return delegation
    return None


def _scope_matches(granted_scope: str, resource_scope: str) -> bool:
    return granted_scope == resource_scope


def _conditions_match(binding: Mapping[str, Any], resource: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    purposes = binding.get("purposes", [])
    if purposes and context.get("purpose") not in purposes:
        return False
    classifications = binding.get("classifications", [])
    if classifications and resource.get("classification") not in classifications:
        return False
    teams = binding.get("teams", [])
    if teams and resource.get("team_id") not in teams:
        return False
    return True


def _direct_grant_allows(
    policy: Mapping[str, Any],
    actor_id: str,
    action: str,
    resource: Mapping[str, Any],
    context: Mapping[str, Any],
) -> bool:
    resource_scope = str(resource.get("scope", ""))
    for grant in policy.get("grants", []):
        if grant.get("actor_id") != actor_id:
            continue
        if action not in grant.get("actions", []):
            continue
        if not any(_scope_matches(str(scope), resource_scope) for scope in grant.get("scopes", [])):
            continue
        if not _conditions_match(grant, resource, context):
            continue
        return True
    return False


def _direct_grant_covers_delegation(
    policy: Mapping[str, Any],
    actor_id: str,
    delegation: Mapping[str, Any],
) -> bool:
    wanted_actions = set(delegation.get("actions", []))
    wanted_scopes = set(delegation.get("scopes", []))
    for grant in policy.get("grants", []):
        if grant.get("actor_id") != actor_id:
            continue
        if not wanted_actions.issubset(set(grant.get("actions", []))):
            continue
        if not wanted_scopes.issubset(set(grant.get("scopes", []))):
            continue
        return True
    return False


def _delegation_is_revoked(policy: Mapping[str, Any], delegation_id: str) -> bool:
    revoked = set(policy.get("revoked_delegation_ids", []))
    current = _delegation_by_id(policy, delegation_id)
    seen: set[str] = set()
    while current is not None:
        cid = str(current["id"])
        if cid in seen:
            return True
        seen.add(cid)
        if cid in revoked or current.get("revoked") is True:
            return True
        parent_id = current.get("parent_id")
        if not parent_id:
            return False
        current = _delegation_by_id(policy, str(parent_id))
    return True


def _delegation_chain_valid(
    policy: Mapping[str, Any],
    delegation: Mapping[str, Any],
    at: datetime,
) -> bool:
    max_depth = int(policy.get("max_delegation_depth", 3))
    current = delegation
    depth = 1
    seen: set[str] = set()

    while True:
        cid = str(current["id"])
        if cid in seen or depth > max_depth:
            return False
        seen.add(cid)
        if _delegation_is_revoked(policy, cid):
            return False

        expires_at = current.get("expires_at")
        if expires_at and _parse_time(str(expires_at)) <= at:
            return False

        grantor_id = str(current.get("grantor_actor_id", ""))
        grantee_id = str(current.get("grantee_actor_id", ""))
        if _actor_by_id(policy, grantor_id) is None or _actor_by_id(policy, grantee_id) is None:
            return False

        parent_id = current.get("parent_id")
        if not parent_id:
            grantor = _actor_by_id(policy, grantor_id)
            if grantor is None or "DELEGATE" not in ROLE_ACTION_CEILINGS.get(str(grantor.get("role")), set()):
                return False
            return _direct_grant_covers_delegation(policy, grantor_id, current)

        parent = _delegation_by_id(policy, str(parent_id))
        if parent is None:
            return False
        if parent.get("grantee_actor_id") != grantor_id:
            return False
        if not set(current.get("actions", [])).issubset(set(parent.get("actions", []))):
            return False
        if not set(current.get("scopes", [])).issubset(set(parent.get("scopes", []))):
            return False
        current = parent
        depth += 1


def _delegated_allows(
    policy: Mapping[str, Any],
    actor_id: str,
    action: str,
    resource: Mapping[str, Any],
    context: Mapping[str, Any],
    at: datetime,
) -> bool:
    resource_scope = str(resource.get("scope", ""))
    for delegation in policy.get("delegations", []):
        if delegation.get("grantee_actor_id") != actor_id:
            continue
        if action not in delegation.get("actions", []):
            continue
        if not any(_scope_matches(str(scope), resource_scope) for scope in delegation.get("scopes", [])):
            continue
        if not _conditions_match(delegation, resource, context):
            continue
        if _delegation_chain_valid(policy, delegation, at):
            return True
    return False


def validate_policy(policy: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "tenant_id",
        "actors",
        "grants",
        "delegations",
        "explicit_denies",
        "revoked_delegation_ids",
    }
    missing = sorted(required.difference(policy))
    if missing:
        raise CompanyTwinPolicyError(f"missing top-level fields: {', '.join(missing)}")
    if policy["schema_version"] != "company-twin-p2c/1":
        raise CompanyTwinPolicyError("unsupported schema_version")
    if not isinstance(policy["tenant_id"], str) or not policy["tenant_id"]:
        raise CompanyTwinPolicyError("tenant_id must be non-empty")

    actor_ids: set[str] = set()
    principal_ids: set[str] = set()
    for actor in policy["actors"]:
        aid = str(actor.get("id", ""))
        pid = str(actor.get("principal_id", ""))
        if not aid or aid in actor_ids:
            raise CompanyTwinPolicyError("actor ids must be unique and non-empty")
        if not pid or pid in principal_ids:
            raise CompanyTwinPolicyError("principal bindings must be unique and non-empty")
        actor_ids.add(aid)
        principal_ids.add(pid)
        if actor.get("actor_kind") not in ACTOR_KINDS:
            raise CompanyTwinPolicyError(f"{aid} has invalid actor_kind")
        if actor.get("role") not in ROLES:
            raise CompanyTwinPolicyError(f"{aid} has invalid role")
        scopes = actor.get("scopes")
        if not isinstance(scopes, list) or not scopes or len(scopes) != len(set(scopes)):
            raise CompanyTwinPolicyError(f"{aid} requires unique explicit scopes")
        if actor.get("role") == "AGENT":
            if actor.get("actor_kind") != "AGENT":
                raise CompanyTwinPolicyError(f"{aid} AGENT role requires AGENT actor_kind")
            manager_id = actor.get("manager_actor_id")
            manager = _actor_by_id(policy, str(manager_id)) if manager_id else None
            if manager is None or manager.get("actor_kind") != "HUMAN":
                raise CompanyTwinPolicyError(f"{aid} requires a human manager")

    grant_ids: set[str] = set()
    for grant in policy["grants"]:
        gid = str(grant.get("id", ""))
        if not gid or gid in grant_ids:
            raise CompanyTwinPolicyError("grant ids must be unique and non-empty")
        grant_ids.add(gid)
        if grant.get("actor_id") not in actor_ids:
            raise CompanyTwinPolicyError(f"{gid} references unknown actor")
        actions = set(grant.get("actions", []))
        if not actions or not actions.issubset(ACTIONS):
            raise CompanyTwinPolicyError(f"{gid} has invalid actions")
        actor = _actor_by_id(policy, str(grant["actor_id"]))
        assert actor is not None
        if not actions.issubset(ROLE_ACTION_CEILINGS[str(actor["role"])]):
            raise CompanyTwinPolicyError(f"{gid} exceeds role ceiling")
        if not grant.get("scopes"):
            raise CompanyTwinPolicyError(f"{gid} requires scopes")

    delegation_ids: set[str] = set()
    for delegation in policy["delegations"]:
        did = str(delegation.get("id", ""))
        if not did or did in delegation_ids:
            raise CompanyTwinPolicyError("delegation ids must be unique and non-empty")
        delegation_ids.add(did)
        if delegation.get("grantor_actor_id") not in actor_ids or delegation.get("grantee_actor_id") not in actor_ids:
            raise CompanyTwinPolicyError(f"{did} references unknown actor")
        actions = set(delegation.get("actions", []))
        if not actions or not actions.issubset(ACTIONS):
            raise CompanyTwinPolicyError(f"{did} has invalid actions")
        if not delegation.get("scopes"):
            raise CompanyTwinPolicyError(f"{did} requires scopes")
        if delegation.get("expires_at"):
            _parse_time(str(delegation["expires_at"]))

    for delegation in policy["delegations"]:
        parent_id = delegation.get("parent_id")
        if parent_id and parent_id not in delegation_ids:
            raise CompanyTwinPolicyError(f"{delegation['id']} has unknown parent delegation")

    for deny in policy["explicit_denies"]:
        if deny.get("actor_id") not in actor_ids:
            raise CompanyTwinPolicyError("explicit deny references unknown actor")
        if deny.get("action") not in ACTIONS:
            raise CompanyTwinPolicyError("explicit deny has invalid action")
        if not deny.get("scope"):
            raise CompanyTwinPolicyError("explicit deny requires scope")


def _receipt(
    *,
    policy: Mapping[str, Any],
    principal_id: str,
    resource: Mapping[str, Any],
    action: str,
    context: Mapping[str, Any],
    at_text: str,
    decision: str,
    reason: str,
    actor_id: str | None,
    redact_resource: bool = False,
) -> dict[str, Any]:
    resource_ref = "REDACTED" if redact_resource else str(resource.get("id", "UNKNOWN"))
    payload = {
        "schema_version": "company-twin-policy-decision/1",
        "tenant_id": str(policy.get("tenant_id", "")),
        "principal_id": principal_id,
        "actor_id": actor_id,
        "resource_ref": resource_ref,
        "action": action,
        "at": at_text,
        "context": dict(sorted(context.items())),
        "decision": decision,
        "reason": reason,
        "effect": "READ_ONLY_DECISION",
    }
    payload["receipt_sha256"] = _canonical_hash(payload)
    return payload


def evaluate(
    policy: Mapping[str, Any],
    *,
    principal_id: str,
    resource: Mapping[str, Any],
    action: str,
    context: Mapping[str, Any] | None = None,
    at: str,
) -> dict[str, Any]:
    validate_policy(policy)
    context = dict(context or {})
    at_dt = _parse_time(at)
    actor = _actor_by_principal(policy, principal_id)
    if actor is None:
        return _receipt(
            policy=policy,
            principal_id=principal_id,
            resource=resource,
            action=action,
            context=context,
            at_text=at,
            decision="DENY",
            reason="UNKNOWN_PRINCIPAL",
            actor_id=None,
            redact_resource=True,
        )

    actor_id = str(actor["id"])
    if action not in ACTIONS:
        return _receipt(
            policy=policy, principal_id=principal_id, resource=resource, action=action,
            context=context, at_text=at, decision="DENY", reason="UNKNOWN_ACTION",
            actor_id=actor_id,
        )

    if resource.get("tenant_id") != policy.get("tenant_id"):
        return _receipt(
            policy=policy, principal_id=principal_id, resource=resource, action=action,
            context=context, at_text=at, decision="DENY", reason="CROSS_TENANT",
            actor_id=actor_id, redact_resource=True,
        )

    role = str(actor["role"])
    if action not in ROLE_ACTION_CEILINGS[role]:
        reason = "AGENT_AUTHORITY_CEILING" if role == "AGENT" else "ROLE_AUTHORITY_CEILING"
        return _receipt(
            policy=policy, principal_id=principal_id, resource=resource, action=action,
            context=context, at_text=at, decision="DENY", reason=reason,
            actor_id=actor_id,
        )

    resource_scope = str(resource.get("scope", ""))
    if resource_scope not in set(actor.get("scopes", [])) and role != "AGENT":
        if not _delegated_allows(policy, actor_id, action, resource, context, at_dt):
            return _receipt(
                policy=policy, principal_id=principal_id, resource=resource, action=action,
                context=context, at_text=at, decision="DENY", reason="SCOPE_NOT_GRANTED",
                actor_id=actor_id,
            )

    acl_scopes = set(resource.get("source_acl_scopes", []))
    if acl_scopes:
        actor_scopes = set(actor.get("scopes", []))
        delegated_scopes = {
            scope
            for delegation in policy.get("delegations", [])
            if delegation.get("grantee_actor_id") == actor_id
            and _delegation_chain_valid(policy, delegation, at_dt)
            for scope in delegation.get("scopes", [])
        }
        if not (acl_scopes & (actor_scopes | delegated_scopes)):
            return _receipt(
                policy=policy, principal_id=principal_id, resource=resource, action=action,
                context=context, at_text=at, decision="DENY", reason="SOURCE_ACL_RESTRICTS",
                actor_id=actor_id,
            )

    for deny in policy.get("explicit_denies", []):
        if deny.get("actor_id") == actor_id and deny.get("action") == action and deny.get("scope") == resource_scope:
            return _receipt(
                policy=policy, principal_id=principal_id, resource=resource, action=action,
                context=context, at_text=at, decision="DENY", reason="EXPLICIT_DENY",
                actor_id=actor_id,
            )

    direct = _direct_grant_allows(policy, actor_id, action, resource, context)
    delegated = _delegated_allows(policy, actor_id, action, resource, context, at_dt)

    if role == "AGENT":
        manager = _actor_by_id(policy, str(actor.get("manager_actor_id", "")))
        if manager is None or manager.get("actor_kind") != "HUMAN":
            return _receipt(
                policy=policy, principal_id=principal_id, resource=resource, action=action,
                context=context, at_text=at, decision="DENY", reason="AGENT_MANAGER_REQUIRED",
                actor_id=actor_id,
            )
        direct = False

    if not (direct or delegated):
        return _receipt(
            policy=policy, principal_id=principal_id, resource=resource, action=action,
            context=context, at_text=at, decision="DENY", reason="NO_MATCHING_GRANT",
            actor_id=actor_id,
        )

    return _receipt(
        policy=policy, principal_id=principal_id, resource=resource, action=action,
        context=context, at_text=at, decision="ALLOW", reason="POLICY_ALLOW",
        actor_id=actor_id,
    )


def plan_lifecycle(
    policy: Mapping[str, Any],
    *,
    principal_id: str,
    resource: Mapping[str, Any],
    operation: str,
    context: Mapping[str, Any] | None = None,
    at: str,
) -> dict[str, Any]:
    if operation not in LIFECYCLE_OPERATIONS:
        raise CompanyTwinPolicyError("unsupported lifecycle operation")
    action = "DELETE" if operation == "RETENTION_PURGE" else operation
    decision = evaluate(
        policy,
        principal_id=principal_id,
        resource=resource,
        action=action,
        context=context,
        at=at,
    )
    allowed = decision["decision"] == "ALLOW"
    reason = decision["reason"]
    if operation in {"DELETE", "RETENTION_PURGE"} and resource.get("legal_hold") is True:
        allowed = False
        reason = "LEGAL_HOLD_BLOCKS_DESTRUCTIVE_PLAN"

    plan = {
        "schema_version": "company-twin-lifecycle-plan/1",
        "tenant_id": str(policy.get("tenant_id", "")),
        "principal_id": principal_id,
        "resource_ref": decision["resource_ref"],
        "operation": operation,
        "at": at,
        "authorized": allowed,
        "reason": reason,
        "effect": "PLAN_ONLY",
        "mutated": False,
        "policy_receipt_sha256": decision["receipt_sha256"],
    }
    plan["plan_sha256"] = _canonical_hash(plan)
    return plan


def revoke_delegation_plan(
    policy: Mapping[str, Any],
    *,
    principal_id: str,
    delegation_id: str,
    at: str,
) -> dict[str, Any]:
    validate_policy(policy)
    delegation = _delegation_by_id(policy, delegation_id)
    synthetic_resource = {
        "id": f"delegation:{delegation_id}",
        "tenant_id": policy["tenant_id"],
        "scope": "company",
        "source_acl_scopes": ["company"],
        "classification": "INTERNAL",
    }
    decision = evaluate(
        policy,
        principal_id=principal_id,
        resource=synthetic_resource,
        action="REVOKE",
        context={"purpose": "governance"},
        at=at,
    )
    descendants: list[str] = []
    if delegation is not None:
        frontier = [delegation_id]
        while frontier:
            parent = frontier.pop()
            for child in policy.get("delegations", []):
                if child.get("parent_id") == parent and child["id"] not in descendants:
                    descendants.append(str(child["id"]))
                    frontier.append(str(child["id"]))
    result = {
        "schema_version": "company-twin-revocation-plan/1",
        "tenant_id": policy["tenant_id"],
        "delegation_id": delegation_id,
        "authorized": decision["decision"] == "ALLOW" and delegation is not None,
        "cascade_delegation_ids": sorted(descendants),
        "effect": "PLAN_ONLY",
        "mutated": False,
        "policy_receipt_sha256": decision["receipt_sha256"],
        "at": at,
    }
    result["plan_sha256"] = _canonical_hash(result)
    return result


def with_revocation(policy: Mapping[str, Any], delegation_id: str) -> dict[str, Any]:
    """Pure helper for tests/planners; returns a copy with a revocation marker."""
    copy = deepcopy(policy)
    ids = set(copy.get("revoked_delegation_ids", []))
    ids.add(delegation_id)
    copy["revoked_delegation_ids"] = sorted(ids)
    return copy
