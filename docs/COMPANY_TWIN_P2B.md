# Company Twin P2B — Canonical Ingestion Contracts

Status: **synthetic-only candidate**  
Parent: Issue #125  
Depends on: P2A / PR #124 merged as `72f3811c8bdd9def7b29c79dad4f2172f462af9d`

## Product line

P2B is built around the same operating model ContinuityOS itself is moving toward:

```text
DIRECTOR
   ↓
HUMAN WORKERS / TEAMS
   ↓
COMPANY MEMORY + DECISIONS + EVIDENCE
   ↓
MANAGED AGENTS / ROBOTS
```

Humans and agents are represented as actors in the same organizational history. An
agent is never treated as an implicit authority source. Every `AGENT` source actor
must declare `manager_actor_id` and is limited in P2B to `NONE`, `READ_ONLY`, or
`PROPOSE`. Execution authority is explicitly outside this layer.

## Why P2B exists

P2A proved that Company Twin can replay a governed organization through time. P2B
defines how heterogeneous history enters that memory without losing identity,
revision history, ACLs, provenance, deletion state, or batch checkpoints.

The target commercial workflow is **One Year Company Twin**:

1. receive authorized history or exports;
2. wrap every object in a canonical source envelope;
3. normalize deterministically;
4. quarantine malformed/ambiguous objects;
5. preserve source ACL and provenance;
6. commit a deterministic receipt and checkpoint;
7. project accepted evidence into the P2A Company Twin timeline.

No live connector is required to prove P2B.

## Canonical source envelope

Required identity and provenance:

- tenant id;
- connector id;
- source system/object type/object id;
- source revision;
- observed and effective timestamps;
- ACL visibility + canonical scope;
- content hash;
- raw evidence reference;
- deletion/tombstone flag;
- connector cursor;
- actor identity, kind, role, manager, and authority class.

The normalized record gets a deterministic canonical id. Re-exporting the same
source object/revision therefore cannot create a second canonical fact.

## Director / worker / company / robot semantics

The synthetic fixture `ContinuityOS Lab` contains:

- a human director;
- engineering and operations workers;
- company-wide evidence;
- team-only evidence;
- restricted finance evidence;
- a managed research robot that may propose but cannot execute.

This is not a permission-engine replacement. P2B preserves source ACLs and actor
management metadata for P2C, which will qualify tenant isolation and enterprise
RBAC/ABAC.

## Deterministic ingestion behavior

### Idempotency

Same tenant + source identity + revision → same canonical record id. A repeated
revision is returned as idempotent rather than duplicated.

### Revision lineage

A newer revision creates a new immutable record and points to the previous record
through `supersedes`. Historical revisions remain replayable.

### Tombstones

Deletion is represented as a revision. Replay before deletion yields the previous
content; replay after deletion yields a tombstone and no active content.

### Cross-export duplicates

Byte-equivalent evidence arriving under a different source identity is marked with
`duplicate_of` but is not silently collapsed. Provenance remains intact.

### ACL propagation

Canonical scope is derived from source ACL and may not be broadened by the
normalizer. Restricted finance remains restricted finance. P2B replay filters before
returning identifiers or payload.

### Quarantine

Malformed envelopes, invalid ACL mappings, hash mismatches, or unmanaged agents are
quarantined. They do not enter accepted organizational memory.

### Transactional checkpoint

The synthetic store commits records and connector cursor only at one commit point.
A simulated pre-commit failure proves both records and cursor remain unchanged.

## Runtime boundaries

P2B is a pure library/test capability.

It does **not**:

- call Google, Slack, Gmail, GitHub, CRM, or any network API;
- mutate the active Sovereign Twin R21H memory or admissions;
- load/unload models;
- grant execution authority;
- trade or move capital;
- connect a real customer tenant.

## Acceptance evidence

The P2B test corpus qualifies:

1. deterministic envelope and receipt schemas;
2. our own ContinuityOS Lab organization fixture;
3. three source families: Drive, Slack, GitHub;
4. same-revision idempotency;
5. batch reordering determinism;
6. cursor rollback on failed batch;
7. immutable revision lineage;
8. as-of tombstone replay;
9. ACL preservation and restricted metadata non-leakage;
10. fail-closed quarantine;
11. managed robot/agent semantics;
12. cross-export duplicate marking without evidence destruction;
13. source-to-P2A provenance projection;
14. no network connector calls.

## Next gate — P2C

P2C should qualify the policy plane above this ingestion layer:

- tenant isolation;
- principal/actor binding;
- Director / Worker / Agent role inheritance;
- RBAC + ABAC;
- personal/team/company boundary rules;
- delegation and revocation;
- retention, deletion, export, legal hold;
- agent authority ceilings and approval chains.

Only after that should a real company-history connector pilot be considered.
