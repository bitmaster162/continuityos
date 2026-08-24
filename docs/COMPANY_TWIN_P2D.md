# Company Twin P2D — Operating Console

## Status

Synthetic-only, read-only productization layer above the qualified Company Twin stack.

P2D composes, rather than replaces:

- P1 Control Center — local runtime/memory/model/governance observability;
- P2A Company Twin — temporal replay, evidence, decisions, outcomes and relationship graph;
- P2C Policy Plane — principal→actor binding, RBAC+ABAC, source-ACL intersection, bounded delegation and managed-agent ceilings.

The organization model is:

`DIRECTOR → HUMAN WORKERS / TEAMS → COMPANY MEMORY → MANAGED AGENTS / ROBOTS`

## Product objective

Give a Director one operating surface for:

- organizational memory;
- decision history and visible lineage;
- human workers and teams;
- managed AI/robot workers;
- policy-backed capabilities;
- agent proposals;
- plan-only lifecycle previews.

P2D is not an execution console. It does not authorize or perform real actions.

## Truth and authority boundaries

P2D preserves these invariants:

- `read_only=true`
- `execution_authority=NONE`
- `can_execute=false`
- `can_trade=false`
- `capital_permission=DENY`
- managed agents may be shown `READ` / `PROPOSE` only where P2C allows them;
- `EXECUTE` is not a P2C/P2D policy action;
- no live OAuth/SSO/SCIM;
- no real company/customer data;
- no destructive retention/delete operations;
- no model load/unload;
- no active R21H cutover.

## Composition contract

### Temporal state

P2D calls `continuityos.company_twin.replay()` for the selected principal and `as_of` timestamp. It does not implement a second temporal-memory engine.

### Policy

Every P2A-visible record is then evaluated through `continuityos.company_twin_policy.evaluate(..., action="READ")`.

P2C can therefore narrow P2A visibility. P2D never broadens it.

After policy filtering, references are pruned again. This prevents a remaining event, relationship, decision or inference from leaking a record identifier removed by policy.

Decision `replay_status` is recomputed from the remaining visible decisions so a hidden superseding decision cannot leak through status metadata.

### Policy receipts

The console exposes receipts only for records that survive both P2A replay and P2C filtering/reference pruning.

Denied-record receipts are not exposed because even a redacted denial set can become a side channel for counts or resource existence.

### Cross-tenant records

If an otherwise P2A-visible synthetic record carries a foreign `tenant_id`, P2C returns `CROSS_TENANT`. P2D drops the record and does not expose its ID, title, receipt or count contribution.

## Role-aware views

### Director

The Director can see the actor graph and all memory that P2C explicitly authorizes, including restricted finance where the finance-purpose grant applies.

The Director sees company timeline, visible decisions and lineage, evidence, synthetic organizational actors, managed-agent delegation metadata, pending proposals allowed by policy, and lifecycle previews for EXPORT / DELETE / LEGAL_HOLD.

Lifecycle previews are `PLAN_ONLY` and `mutated=false`.

### Worker

A worker sees only records surviving both P2A scope replay and P2C policy.

An Engineering Worker may see Company + Engineering records allowed by the matching ABAC purpose.

An Operations Worker may see Company + Operations records. Engineering-only identifiers are absent from navigation, counts, graph, timeline, receipts and errors.

### Managed Agent / Robot

The Research Robot is a first-class `AGENT` actor with a human manager.

Its console view exposes manager, own delegation, allowed engineering records, proposal history allowed by policy, and policy-backed capabilities.

Its authority panel must show:

- `READ`: bounded by delegation/ACL/ABAC;
- `PROPOSE`: bounded by delegation/ACL/ABAC;
- `APPROVE`: denied by agent authority ceiling;
- `EXECUTE`: unavailable (`NOT_IN_P2C_POLICY_ACTIONS`).

The robot does not inherit its manager's broader authority.

## Synthetic ContinuityOS Lab fixture

The source fixture is `examples/company_twin_console/continuityos_lab_console.json`.

It uses P2A-compatible memory records whose principals match the P2C principal bindings:

- `principal_director`
- `principal_eng_worker`
- `principal_ops_worker`
- `principal_research_robot`

The fixture references the already-qualified P2C policy source at `../company_twin_policy/continuityos_lab_policy.json`.

Evidence references reuse synthetic P2B-style source URIs such as `synthetic://drive/...`, `synthetic://slack/...`, and `synthetic://github/...`. This is composition evidence, not a live connector.

## HTTP surface

Default bind: `127.0.0.1:8768`

Routes:

- `GET /` — static read-only UI;
- `GET /api/snapshot?principal=<id>&as_of=<timestamp>` — deterministic snapshot;
- `HEAD` mirrors the read routes without a body.

`POST`, `PUT`, `PATCH`, and `DELETE` return HTTP 405.

Non-loopback bind is refused before server creation.

The UI writes snapshot content only through `textContent`; it does not use `innerHTML`.

## Packaging rule

The installed wheel must not depend on `examples/` or `docs/`.

`synthetic_demo_bundle()` is the portable wheel-test fixture.

The source fixture is checked only when it exists in the source checkout, following the established P2C wheel-only pattern.

## P2D acceptance

P2D is qualified only when:

1. Director/Worker/Agent snapshots enforce P2A+P2C intersection;
2. restricted and cross-tenant IDs do not leak;
3. historical replay changes state deterministically;
4. visible decision lineage remains inspectable;
5. managed-agent READ/PROPOSE ceilings are explicit;
6. policy receipts map only to visible records;
7. lifecycle operations remain plan-only;
8. loopback-only and HTTP write-deny tests pass;
9. source tests pass;
10. wheel-only tests pass on Ubuntu and Windows;
11. full editable regression passes;
12. P0 and CodeQL pass.

A green P2D PR is only merge-ready. Merge requires a separate exact-head approval.
