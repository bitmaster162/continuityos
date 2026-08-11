# Project Memory Bootstrap v1 (R38)

R35–R37 close the live project-memory loop once a Common Operational Memory database already exists:

```text
current-work -> delta proposal -> separately authorized atomic apply
```

R38 removes the remaining manual seed step for a **new** project database. One declarative manifest binds project facts to exact evidence files; one separate authorization binds the raw manifest and exact target path. The result is a verified shadow OperationalMemory database that can immediately be read by `continuity-work` and later synchronized through R36/R37.

## Command

```text
continuity-memory-bootstrap \
  --db /local/path/project.db \
  --manifest /local/path/bootstrap-manifest.json \
  --authorization /local/path/bootstrap-authorization.json
```

The target parent directory must already exist. The target database must not already contain unrelated data. Existing project databases are never overwritten; use R36/R37 for later changes.

A declared current R64 session is refused before target creation. Bootstrap is a separate effectful operation and does not make the current session writable.

## Manifest

Schema:

```text
continuityos.operational_memory.project_bootstrap_manifest/v1
```

Fields:

- `schema`
- `project_id`
- `evidence`
- `claims`
- `proposed_decisions`
- optional `rationale`

Each evidence row has a stable `evidence_id`, exact SHA-256 and local `locator`, with optional `kind` and `scope`. R38 rereads every evidence file and verifies its raw bytes before creating the temporary database. Symlink/reparse evidence inputs are refused.

Each claim specifies:

- `predicate`
- `scope`
- `value`
- `evidence_state`
- `evidence_ids`
- `valid_from`
- optional `valid_to`
- `recorded_at`

A non-`UNKNOWN` claim must reference verified evidence. Duplicate `predicate+scope` identities are rejected so bootstrap cannot create split current truth.

`proposed_decisions` deliberately have no `state` or accepted authority fields. Every bootstrap decision is recorded as `PROPOSED`, `authority_class=AGENT`. Accepted/HOLD/rejected decisions must enter later through the explicit OperationalMemory decision/apply authority path.

## Authorization

Schema:

```text
continuityos.operational_memory.project_bootstrap_authorization/v1
```

Decision:

```text
APPROVE_SHADOW_PROJECT_MEMORY_BOOTSTRAP
```

The authorization binds:

- raw manifest file SHA-256;
- exact project ID;
- exact absolute target DB path;
- claim count;
- proposed-decision count;
- HUMAN or DETERMINISTIC_CONTROLLER identity/reference;
- bootstrap recorded time and rationale.

As with the R37 local apply authorization, this is an explicit local authority record, not a cryptographic signature. Security domains requiring authenticated identity must wrap or replace it with an authenticated mechanism.

## Publication model

R38 never seeds the final path incrementally.

```text
validate manifest/auth/evidence
        ↓
create temp SQLite in target directory
        ↓
record manifest claims
        ↓
record PROPOSED decisions
        ↓
append PROJECT_MEMORY_BOOTSTRAPPED
        ↓
OperationalMemory.verify()
        ↓
checkpoint WAL
        ↓
atomic no-clobber link to target
        ↓
read-only verify target
```

If validation or construction fails, the target is absent and temporary files are removed. If another process creates the target first, publication fails rather than overwriting it.

Exact replay against an already bootstrapped target returns `PROJECT_MEMORY_BOOTSTRAP_ALREADY_CREATED` without appending events.

## Authority boundary

Bootstrap creates only **shadow OperationalMemory**. It does not change accepted truth or canonical R64 state. Success still reports:

- `accepted_truth_modified=false`
- `current_state_apply=false`
- `canonical_mutation=false`
- `deployment=false`
- `agent_dispatch=false`
- `external_message=false`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

Once the project DB exists, do not rerun bootstrap to update it. Use `continuity-work` to inspect, `continuity-memory-delta` to propose a change under the verified current session, and `continuity-memory-apply` for separately authorized atomic shadow-memory synchronization.