# Company Twin P2C — Director / Worker / Agent Policy Plane

Status: candidate specification accompanying `continuityos.company_twin_policy`.

## Organizational line

```text
DIRECTOR
  ↓
HUMAN WORKERS / TEAMS
  ↓
COMPANY MEMORY
  ↓
MANAGED AGENTS / ROBOTS
```

P2C treats humans and agents as explicit organizational actors. It does not give an agent execution authority merely because it is connected, useful, or managed by a privileged human.

## Scope

P2C qualifies deterministic, read-only policy decisions over synthetic `ContinuityOS Lab` data. It sits above P2A historical replay and P2B canonical ingestion.

It introduces hard tenant boundaries, principal→actor binding, roles (`DIRECTOR`, `WORKER`, `AGENT`, `SERVICE`), explicit scopes, RBAC ceilings, ABAC conditions for purpose/classification/team, source-ACL intersection, explicit-deny precedence, bounded delegation/expiry/revocation, managed-agent ceilings, deterministic receipts, and plan-only lifecycle/revocation output.

## Director

Director is a human actor with explicit grants. Director status does not bypass tenant boundaries, source ACL, explicit deny, legal hold, retention constraints, or missing policy bindings. Delegation cannot exceed the Director's explicit grant.

## Worker

Worker is a human actor with explicit company/team scopes. P2C worker action ceiling is `READ` and `PROPOSE`. Workers do not inherit restricted finance or another team's access from broad company metadata.

## Managed agent / robot

An `AGENT` must have a unique principal→actor binding, a human manager, an active valid delegation, and stay inside delegated scope, source ACL and ABAC context.

P2C agent ceiling is:

```text
READ
PROPOSE
```

`APPROVE`, `DELEGATE`, `REVOKE`, `EXPORT`, `DELETE`, `LEGAL_HOLD`, and future `EXECUTE` are not implicitly available to an agent. `EXECUTE` is intentionally not a P2C action and belongs to a later separately authorized governance layer.

## Fail-closed evaluation order

1. validate policy contract;
2. resolve principal→actor;
3. reject unknown action;
4. enforce exact tenant;
5. enforce role/agent ceiling;
6. enforce actor/delegated scope;
7. intersect source ACL;
8. apply explicit deny;
9. match direct or delegated grant;
10. match ABAC purpose/classification/team;
11. emit deterministic `ALLOW`/`DENY` receipt.

Cross-tenant denial redacts resource identity in the receipt.

## Delegation

Delegations are bounded by the root grantor's explicit grant, parent action/scope subset, maximum depth, expiry, and revocation. Revoking a parent invalidates descendants at evaluation time.

No mutation API is provided. `with_revocation()` returns a copied policy for tests/planning only.

## Lifecycle planning

P2C can plan `EXPORT`, `DELETE`, `RETENTION_PURGE`, and `LEGAL_HOLD`. Plans have `effect=PLAN_ONLY` and `mutated=false`. Legal hold blocks destructive delete/purge planning but does not broaden read visibility.

## Synthetic ContinuityOS Lab

The fixture contains a ContinuityOS Director, Engineering Worker, Operations Worker, and Research Robot managed by Engineering, plus company/team/restricted scopes, explicit worker denies, and a bounded Director→Robot `READ/PROPOSE` delegation.

No customer identity, customer data, credentials, OAuth token, live connector, or active ContinuityOS memory is used.

## Non-goals

- autonomous robot execution;
- production tenant provisioning;
- live SSO/SCIM;
- destructive retention purge;
- real-company identities/data;
- active deployment into Sovereign Twin R21H;
- trading/capital authority.

## Exit criteria

CI must prove tenant isolation, worker scope boundaries, source ACL precedence, managed-agent delegation, `READ/PROPOSE` ceiling, ABAC deny, expiry/revocation, bounded delegation, deterministic receipts, plan-only lifecycle, and isolated-wheel portability.
