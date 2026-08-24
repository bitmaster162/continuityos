# Company Twin P2E-R4 — Lifecycle, retention, export, and tombstone semantics

P2E-R4 closes the lifecycle-policy gap identified by the Company Twin parent issue. It is a pure, in-memory contract layer. It does not delete files, mutate source systems, change the local Sovereign Twin runtime, or grant execution authority.

## Boundary

- exact tenant-bound record IDs only for tombstone requests;
- no title/fuzzy/semantic/model-selected deletion;
- tombstone-first logical lifecycle;
- no physical delete or purge executor;
- deterministic retention classes;
- explicit hold blocks purge eligibility;
- active references block purge eligibility;
- purge result is advisory only;
- tenant/scope-filtered read-only exports;
- deterministic export manifest and receipt hashes;
- agents cannot tombstone, set retention, manage holds, or purge;
- agent export remains bounded to caller-supplied authorized scopes and does not elevate authority.

## Retention classes

| Class | Default retention |
| --- | --- |
| `TRANSIENT` | 30 days |
| `STANDARD` | 365 days |
| `EXTENDED` | 2555 days |
| `INDEFINITE` | no expiry |

Retention assignment and hold management require a `HUMAN` principal with `OWNER` authority.

## Tombstone flow

`request_tombstone()` resolves exactly one record using `(tenant_id, record_id)`. It returns a deterministic logical event and never mutates the supplied record set.

`build_tombstone_envelope()` turns that event into a new P2B-compatible source revision with `deleted=true`. The existing P2B normalization/supersession model then preserves historical replay: an earlier cutoff returns the original active record; a later cutoff returns the tombstone.

The envelope preserves source-system identity and ACL scope. Its payload is empty. It is a new revision, not an in-place destructive edit.

## Purge eligibility

`purge_eligibility()` is advisory. It can return `eligible=true`, but it never performs deletion.

Blocking reasons are deterministic:

- `NOT_TOMBSTONED`
- `HOLD_ACTIVE`
- `RETENTION_INDEFINITE`
- `RETENTION_NOT_EXPIRED`
- `ACTIVE_REFERENCES`

An eligible result still carries `advisory_only=true` and `physical_delete=false`.

## Export

`build_export_bundle()` emits a deterministic read-only bundle filtered by:

1. exact `tenant_id`;
2. caller-supplied authorized scopes;
3. optional tombstone inclusion.

The bundle retains truth/provenance fields, sorts records deterministically, and includes `manifest_hash` and `receipt_hash`.

Cross-tenant and unauthorized-scope records are not exported.

## Authority ceiling

Lifecycle management remains owner-only. `AGENT` principals are denied tombstone, retention, hold release/set, and purge operations. No execution path is added.

## Non-goals

P2E-R4 does not:

- physically delete GitHub, Drive, local, runtime, or customer data;
- mutate canonical memory/admissions;
- deploy or start runtime services;
- add a Drive/Gmail/Slack connector;
- perform OAuth;
- enable robot execution;
- change trading/capital authority.

Parent: #123  
Work order: #141
