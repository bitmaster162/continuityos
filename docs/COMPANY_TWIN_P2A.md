# Company Twin P2A — Synthetic 12‑Month Organizational Memory

Status: **design-qualified prototype candidate**  
Runtime boundary: **read-only / no active R21H changes / no customer data**

## Goal

P2A proves the core Company Twin thesis on a synthetic company before any real connector or customer-data ingestion:

> Turn a year of scattered company activity into governed institutional memory that people and AI can safely replay.

This is not enterprise search and not a chatbot trained on documents. The prototype models **time, evidence, decisions, outcomes, relationships, permissions, and inference** as separate first-class concepts.

## Product hierarchy

```text
ContinuityOS
├── Person Twin
├── Team Twin
├── Company Twin
│   ├── Organizational Timeline
│   ├── Decision Ledger
│   ├── Entity / Relationship Graph
│   ├── Evidence Lineage
│   ├── Historical Replay
│   └── Permission Scopes
├── Company AI
└── Governed Agents
```

P2A stops at the **read-only Company Twin** layer. It does not grant execution authority.

## Synthetic fixture

`examples/company_twin/northstar_labs_2025.json`

The fixture contains a synthetic B2B SaaS company, Northstar Labs, from January through December 2025. It includes:

- four principals with different scope sets;
- company/team/restricted/personal permission scopes;
- entities and relationships;
- source authorities;
- evidence records;
- at least one historical event in every month;
- a decision ledger with supersession;
- observed outcomes;
- process observations;
- explicit model inferences.

No real person, company, credential, customer, or production system is represented.

## Truth classes

P2A never collapses source history and model interpretation.

### `EVIDENCE`

An immutable reference to a source artifact or source-derived observation.

### `FACT`

A structured historical assertion backed by evidence, such as an event, decision, relationship, or observed outcome.

### `INFERENCE`

A model or analytical interpretation. Inferences must cite supporting evidence/events/decisions and remain visibly distinct from historical evidence.

## Permission model

Every first-class record has exactly one `scope`.

Representative scopes:

```text
company
team:sales
team:product
team:engineering
restricted:finance
person:<principal>
```

Every principal has an explicit list of allowed scopes. Replay is **fail closed**:

- records outside the principal's scopes are not returned;
- if a visible record references evidence/entity/decision outside the principal's scope, the referencing record is also hidden;
- restricted identifiers therefore do not leak through metadata references;
- unknown principals fail;
- remote network exposure is rejected by the Explorer.

This is a P2A scope model, not the final enterprise RBAC/ABAC design.

## Historical replay

`continuityos.company_twin.replay(...)` reconstructs what a principal is allowed to see at an exact historical timestamp.

The replay engine:

1. validates the dataset;
2. resolves the principal's scopes;
3. filters every record by time;
4. filters every record by scope;
5. fails closed on cross-scope references;
6. calculates decision supersession status;
7. retains explicit `FACT / EVIDENCE / INFERENCE` separation.

A replay is deterministic and read-only.

```python
from continuityos.company_twin import load_dataset, replay

data = load_dataset("examples/company_twin/northstar_labs_2025.json")
snapshot = replay(data, principal_id="bob", as_of="2025-10-31T23:59:59Z")
```

## Decision ledger

A decision contains timestamp, scope, rationale, evidence references, and optional `supersedes`. Replay assigns `ACTIVE` or `SUPERSEDED`. `decision_lineage(...)` walks visible decision history backward without crossing a permission boundary.

## Entity graph

P2A models entities and temporal relationships separately from prose. The fixture includes organization, product, teams, customers and a restricted financial plan, with relationships such as `OWNS`, `BUILDS`, `SERVES`, and `GOVERNS_BUDGET`.

## Read-only Explorer

Module: `continuityos.company_twin_explorer`

Run from a source checkout:

```bash
python -m continuityos.company_twin_explorer --fixture examples/company_twin/northstar_labs_2025.json
```

Default: `http://127.0.0.1:8767`

Routes:

```text
GET /
GET /health
GET /api/meta
GET /api/replay?principal=<id>&as_of=<timestamp>
```

All mutation verbs return `405`. The service is loopback-only. The UI exposes principal selection, replay date, visible record counts, historical timeline, raw replay snapshot, and explicit truth classes. It has no agent actions, no write path, no model load/unload route, and no customer-data connector.

## Acceptance properties

P2A tests prove:

1. synthetic data covers all 12 months;
2. replay changes with time and does not mutate source data;
3. sales scope cannot observe restricted-finance records or identifiers;
4. cross-scope references fail closed;
5. executive scope can observe authorized finance records;
6. decision supersession and lineage are historically correct;
7. `FACT`, `EVIDENCE`, and `INFERENCE` remain distinct;
8. unknown principals and out-of-period replay fail;
9. Explorer is loopback-only;
10. POST/PUT/PATCH/DELETE are rejected;
11. UI uses safe text rendering and contains no mutation calls.

## What P2A does not claim

P2A is **not** a production multi-tenant service, final RBAC/ABAC system, live connector implementation, ingestion pipeline, customer-data processing system, autonomous company agent, execution-authorized system, or replacement for R21H.

No active Sovereign Twin runtime state, canonical memory, admissions, model residency, or execution authority is changed by this prototype.

## Next gates after P2A

### P2B — ingestion contracts

Define canonical source envelope, connector cursor/checkpoint semantics, ingestion idempotency, deduplication, source deletion/tombstones, provenance preservation, and source authority ranking. Start with synthetic connector fixtures before live APIs.

### P2C — tenant and permission model

Add tenant isolation, groups/roles, ABAC attributes, restricted compartments, source-level ACL inheritance, row/object scope, access audit, deletion/export/retention.

### P2D — Company Twin UX

Add organizational timeline, decision explorer, entity graph, key-person dependency view, repeated-failure patterns, historical replay query, and source/evidence viewer.

### P2E — real pilot

Only after privacy, retention, deletion, export, tenant isolation, and connector security are separately qualified should real company data be admitted.

## Commercial hypothesis

A possible onboarding product:

> **One Year Company Twin** — connect an authorized year of company history and receive a governed, replayable institutional memory layer.

Potential outputs include organizational timeline, decision map, customer/project memory, recurring process map, repeated-failure patterns, key-person dependency map, and searchable historical replay.

The durable differentiator is not storage or embeddings. It is:

```text
Time + Evidence + Decisions + Outcomes + Permissions + Replay
```
