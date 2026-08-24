from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import continuityos.company_twin_policy as p


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "company_twin_policy" / "continuityos_lab_policy.json"
AT = "2026-08-24T00:00:00Z"

_PORTABLE_POLICY = {'actors': [{'actor_kind': 'HUMAN',
             'id': 'actor_director',
             'name': 'ContinuityOS Director',
             'principal_id': 'principal_director',
             'role': 'DIRECTOR',
             'scopes': ['company', 'team:engineering', 'team:operations', 'restricted:finance']},
            {'actor_kind': 'HUMAN',
             'id': 'actor_eng',
             'name': 'Engineering Worker',
             'principal_id': 'principal_eng_worker',
             'role': 'WORKER',
             'scopes': ['company', 'team:engineering']},
            {'actor_kind': 'HUMAN',
             'id': 'actor_ops',
             'name': 'Operations Worker',
             'principal_id': 'principal_ops_worker',
             'role': 'WORKER',
             'scopes': ['company', 'team:operations']},
            {'actor_kind': 'AGENT',
             'id': 'actor_robot',
             'manager_actor_id': 'actor_eng',
             'name': 'Research Robot',
             'principal_id': 'principal_research_robot',
             'role': 'AGENT',
             'scopes': ['team:engineering']}],
 'delegations': [{'actions': ['READ', 'PROPOSE'],
                  'classifications': ['PUBLIC', 'INTERNAL'],
                  'expires_at': '2026-12-31T23:59:59Z',
                  'grantee_actor_id': 'actor_robot',
                  'grantor_actor_id': 'actor_director',
                  'id': 'deleg_director_robot_eng',
                  'purposes': ['research'],
                  'scopes': ['team:engineering']}],
 'explicit_denies': [{'action': 'READ',
                      'actor_id': 'actor_eng',
                      'id': 'deny_eng_fin',
                      'scope': 'restricted:finance'},
                     {'action': 'READ',
                      'actor_id': 'actor_ops',
                      'id': 'deny_ops_eng',
                      'scope': 'team:engineering'}],
 'grants': [{'actions': ['READ',
                         'PROPOSE',
                         'APPROVE',
                         'DELEGATE',
                         'REVOKE',
                         'EXPORT',
                         'DELETE',
                         'LEGAL_HOLD'],
             'actor_id': 'actor_director',
             'classifications': ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL'],
             'id': 'grant_director_company',
             'purposes': ['governance', 'operations', 'engineering', 'research', 'audit'],
             'scopes': ['company']},
            {'actions': ['READ',
                         'PROPOSE',
                         'APPROVE',
                         'DELEGATE',
                         'REVOKE',
                         'EXPORT',
                         'DELETE',
                         'LEGAL_HOLD'],
             'actor_id': 'actor_director',
             'classifications': ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL'],
             'id': 'grant_director_eng',
             'purposes': ['governance', 'engineering', 'research', 'audit'],
             'scopes': ['team:engineering']},
            {'actions': ['READ',
                         'PROPOSE',
                         'APPROVE',
                         'DELEGATE',
                         'REVOKE',
                         'EXPORT',
                         'DELETE',
                         'LEGAL_HOLD'],
             'actor_id': 'actor_director',
             'classifications': ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL'],
             'id': 'grant_director_ops',
             'purposes': ['governance', 'operations', 'audit'],
             'scopes': ['team:operations']},
            {'actions': ['READ', 'EXPORT', 'DELETE', 'LEGAL_HOLD'],
             'actor_id': 'actor_director',
             'classifications': ['CONFIDENTIAL', 'RESTRICTED'],
             'id': 'grant_director_fin',
             'purposes': ['governance', 'finance', 'audit'],
             'scopes': ['restricted:finance']},
            {'actions': ['READ', 'PROPOSE'],
             'actor_id': 'actor_eng',
             'classifications': ['PUBLIC', 'INTERNAL'],
             'id': 'grant_eng_company',
             'purposes': ['engineering', 'research'],
             'scopes': ['company']},
            {'actions': ['READ', 'PROPOSE'],
             'actor_id': 'actor_eng',
             'classifications': ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL'],
             'id': 'grant_eng_team',
             'purposes': ['engineering', 'research'],
             'scopes': ['team:engineering']},
            {'actions': ['READ', 'PROPOSE'],
             'actor_id': 'actor_ops',
             'classifications': ['PUBLIC', 'INTERNAL'],
             'id': 'grant_ops_company',
             'purposes': ['operations'],
             'scopes': ['company']},
            {'actions': ['READ', 'PROPOSE'],
             'actor_id': 'actor_ops',
             'classifications': ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL'],
             'id': 'grant_ops_team',
             'purposes': ['operations'],
             'scopes': ['team:operations']}],
 'max_delegation_depth': 3,
 'revoked_delegation_ids': [],
 'schema_version': 'company-twin-p2c/1',
 'tenant_id': 'tenant_continuityos_lab'}


def load_policy():
    return copy.deepcopy(_PORTABLE_POLICY)


def test_source_fixture_matches_portable_contract_when_present():
    if not FIXTURE.exists():
        pytest.skip("source-only Company Twin P2C fixture is not packaged in wheel")
    source = json.loads(FIXTURE.read_text(encoding="utf-8"))
    p.validate_policy(source)
    assert source == _PORTABLE_POLICY


def resource(*, rid="res1", tenant="tenant_continuityos_lab", scope="company",
             acl=None, classification="INTERNAL", team_id=None, legal_hold=False):
    return {
        "id": rid,
        "tenant_id": tenant,
        "scope": scope,
        "source_acl_scopes": list(acl if acl is not None else [scope]),
        "classification": classification,
        "team_id": team_id,
        "legal_hold": legal_hold,
    }


def test_policy_validates():
    p.validate_policy(load_policy())


def test_director_can_read_explicit_company_history():
    d = p.evaluate(
        load_policy(), principal_id="principal_director",
        resource=resource(), action="READ",
        context={"purpose": "governance"}, at=AT,
    )
    assert d["decision"] == "ALLOW"


def test_director_cannot_cross_tenant_and_resource_is_redacted():
    d = p.evaluate(
        load_policy(), principal_id="principal_director",
        resource=resource(rid="secret-other", tenant="tenant_other"),
        action="READ", context={"purpose": "governance"}, at=AT,
    )
    assert d["decision"] == "DENY"
    assert d["reason"] == "CROSS_TENANT"
    assert d["resource_ref"] == "REDACTED"


def test_worker_reads_own_team_with_matching_abac():
    d = p.evaluate(
        load_policy(), principal_id="principal_eng_worker",
        resource=resource(scope="team:engineering", classification="CONFIDENTIAL", team_id="engineering"),
        action="READ", context={"purpose": "engineering"}, at=AT,
    )
    assert d["decision"] == "ALLOW"


def test_worker_denied_other_team():
    d = p.evaluate(
        load_policy(), principal_id="principal_ops_worker",
        resource=resource(scope="team:engineering", team_id="engineering"),
        action="READ", context={"purpose": "operations"}, at=AT,
    )
    assert d["decision"] == "DENY"


def test_worker_denied_restricted_finance_without_explicit_grant():
    d = p.evaluate(
        load_policy(), principal_id="principal_eng_worker",
        resource=resource(scope="restricted:finance", classification="RESTRICTED"),
        action="READ", context={"purpose": "finance"}, at=AT,
    )
    assert d["decision"] == "DENY"


def test_source_acl_more_restrictive_than_company_scope_wins():
    d = p.evaluate(
        load_policy(), principal_id="principal_ops_worker",
        resource=resource(scope="company", acl=["team:engineering"]),
        action="READ", context={"purpose": "operations"}, at=AT,
    )
    assert d["decision"] == "DENY"
    assert d["reason"] == "SOURCE_ACL_RESTRICTS"


def test_abac_purpose_mismatch_denies():
    d = p.evaluate(
        load_policy(), principal_id="principal_eng_worker",
        resource=resource(scope="company"),
        action="READ", context={"purpose": "finance"}, at=AT,
    )
    assert d["decision"] == "DENY"
    assert d["reason"] == "NO_MATCHING_GRANT"


def test_abac_classification_mismatch_denies():
    d = p.evaluate(
        load_policy(), principal_id="principal_eng_worker",
        resource=resource(scope="company", classification="RESTRICTED"),
        action="READ", context={"purpose": "engineering"}, at=AT,
    )
    assert d["decision"] == "DENY"


def test_agent_can_read_inside_delegated_scope_and_acl():
    d = p.evaluate(
        load_policy(), principal_id="principal_research_robot",
        resource=resource(scope="team:engineering", acl=["team:engineering"]),
        action="READ", context={"purpose": "research"}, at=AT,
    )
    assert d["decision"] == "ALLOW"


def test_agent_can_propose_but_not_approve():
    pol = load_policy()
    proposal = p.evaluate(
        pol, principal_id="principal_research_robot",
        resource=resource(scope="team:engineering"),
        action="PROPOSE", context={"purpose": "research"}, at=AT,
    )
    approval = p.evaluate(
        pol, principal_id="principal_research_robot",
        resource=resource(scope="team:engineering"),
        action="APPROVE", context={"purpose": "research"}, at=AT,
    )
    assert proposal["decision"] == "ALLOW"
    assert approval["decision"] == "DENY"
    assert approval["reason"] == "AGENT_AUTHORITY_CEILING"


def test_agent_cannot_execute_unknown_action():
    d = p.evaluate(
        load_policy(), principal_id="principal_research_robot",
        resource=resource(scope="team:engineering"),
        action="EXECUTE", context={"purpose": "research"}, at=AT,
    )
    assert d["decision"] == "DENY"
    assert d["reason"] == "UNKNOWN_ACTION"


def test_agent_requires_human_manager_validation():
    pol = load_policy()
    robot = next(a for a in pol["actors"] if a["id"] == "actor_robot")
    robot["manager_actor_id"] = "missing"
    with pytest.raises(p.CompanyTwinPolicyError):
        p.validate_policy(pol)


def test_expired_agent_delegation_denies():
    pol = load_policy()
    pol["delegations"][0]["expires_at"] = "2026-01-01T00:00:00Z"
    d = p.evaluate(
        pol, principal_id="principal_research_robot",
        resource=resource(scope="team:engineering"),
        action="READ", context={"purpose": "research"}, at=AT,
    )
    assert d["decision"] == "DENY"


def test_revoked_parent_invalidates_descendant_delegation():
    pol = load_policy()
    pol["actors"].append({
        "id": "actor_temp", "principal_id": "principal_temp",
        "name": "Temporary Worker", "actor_kind": "HUMAN",
        "role": "WORKER", "scopes": ["team:engineering"],
    })
    pol["delegations"] = [
        {
            "id": "d_parent", "grantor_actor_id": "actor_director",
            "grantee_actor_id": "actor_eng", "actions": ["READ"],
            "scopes": ["team:engineering"], "expires_at": "2026-12-31T23:59:59Z"
        },
        {
            "id": "d_child", "grantor_actor_id": "actor_eng",
            "grantee_actor_id": "actor_temp", "actions": ["READ"],
            "scopes": ["team:engineering"], "parent_id": "d_parent",
            "expires_at": "2026-12-31T23:59:59Z"
        },
    ]
    before = p.evaluate(
        pol, principal_id="principal_temp",
        resource=resource(scope="team:engineering"),
        action="READ", context={}, at=AT,
    )
    assert before["decision"] == "ALLOW"
    revoked = p.with_revocation(pol, "d_parent")
    after = p.evaluate(
        revoked, principal_id="principal_temp",
        resource=resource(scope="team:engineering"),
        action="READ", context={}, at=AT,
    )
    assert after["decision"] == "DENY"


def test_delegation_cannot_exceed_root_grant():
    pol = load_policy()
    pol["delegations"][0]["scopes"].append("restricted:finance")
    d = p.evaluate(
        pol, principal_id="principal_research_robot",
        resource=resource(scope="team:engineering"),
        action="READ", context={"purpose": "research"}, at=AT,
    )
    assert d["decision"] == "DENY"


def test_role_ceiling_rejects_overpowered_worker_grant():
    pol = load_policy()
    pol["grants"].append({
        "id":"bad", "actor_id":"actor_eng", "actions":["APPROVE"],
        "scopes":["company"]
    })
    with pytest.raises(p.CompanyTwinPolicyError):
        p.validate_policy(pol)


def test_unknown_principal_fails_closed_and_redacts():
    d = p.evaluate(
        load_policy(), principal_id="principal_missing",
        resource=resource(rid="sensitive"),
        action="READ", context={"purpose":"engineering"}, at=AT,
    )
    assert d["decision"] == "DENY"
    assert d["resource_ref"] == "REDACTED"


def test_receipt_is_deterministic():
    kwargs = dict(
        principal_id="principal_eng_worker",
        resource=resource(scope="team:engineering"),
        action="READ", context={"purpose":"engineering"}, at=AT,
    )
    a = p.evaluate(load_policy(), **kwargs)
    b = p.evaluate(load_policy(), **kwargs)
    assert a == b
    assert len(a["receipt_sha256"]) == 64


def test_lifecycle_delete_is_plan_only_and_does_not_mutate():
    pol = load_policy()
    before = copy.deepcopy(pol)
    plan = p.plan_lifecycle(
        pol, principal_id="principal_director",
        resource=resource(), operation="DELETE",
        context={"purpose":"governance"}, at=AT,
    )
    assert plan["authorized"] is True
    assert plan["effect"] == "PLAN_ONLY"
    assert plan["mutated"] is False
    assert pol == before


def test_legal_hold_blocks_destructive_plan():
    plan = p.plan_lifecycle(
        load_policy(), principal_id="principal_director",
        resource=resource(legal_hold=True), operation="RETENTION_PURGE",
        context={"purpose":"governance"}, at=AT,
    )
    assert plan["authorized"] is False
    assert plan["reason"] == "LEGAL_HOLD_BLOCKS_DESTRUCTIVE_PLAN"


def test_export_plan_respects_policy():
    ok = p.plan_lifecycle(
        load_policy(), principal_id="principal_director",
        resource=resource(), operation="EXPORT",
        context={"purpose":"audit"}, at=AT,
    )
    denied = p.plan_lifecycle(
        load_policy(), principal_id="principal_eng_worker",
        resource=resource(), operation="EXPORT",
        context={"purpose":"engineering"}, at=AT,
    )
    assert ok["authorized"] is True
    assert denied["authorized"] is False


def test_revocation_plan_is_plan_only():
    plan = p.revoke_delegation_plan(
        load_policy(), principal_id="principal_director",
        delegation_id="deleg_director_robot_eng", at=AT,
    )
    assert plan["authorized"] is True
    assert plan["effect"] == "PLAN_ONLY"
    assert plan["mutated"] is False


def test_no_mutation_during_policy_evaluation():
    pol = load_policy()
    before = copy.deepcopy(pol)
    _ = p.evaluate(
        pol, principal_id="principal_director",
        resource=resource(), action="READ",
        context={"purpose":"governance"}, at=AT,
    )
    assert pol == before
