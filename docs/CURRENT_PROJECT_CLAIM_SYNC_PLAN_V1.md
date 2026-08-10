# Current Project Claim Sync Plan v1 (R43)

R43 removes manual storage-identity lookup when new evidence updates facts in an **existing** shadow OperationalMemory project.

## Command

```text
continuity-memory-claim-sync-plan --operational-db PROJECT.db --request CLAIM_SYNC_REQUEST.json
```

The command requires an already verified current R64 session and is read-only. It never creates or modifies the database.

## What the request declares

The request contains:

- one `project_id`;
- exact local evidence locators;
- 1–64 desired claims identified by logical `(predicate, scope)` selectors;
- each claim's desired value, evidence state and evidence IDs.

R43 stable-reads and hashes the exact evidence bytes. It does **not** decide whether those bytes semantically prove the requested claim; `semantic_assertions_accepted=false` remains explicit.

## Selector resolution

For every logical claim selector:

- no current claim → generate R36 `RECORD_CLAIM`;
- exactly one current claim → generate R36 `SUPERSEDE_CLAIM` using its exact `claim_id`;
- more than one current claim → fail closed as ambiguous.

R43 then delegates to the existing R36 compiler. R36 re-resolves the supplied current claim ID and binds its exact `claim_hash`, projection SHA, event cursor, event chain head and current-work capsule SHA.

The output therefore contains a normal R36 base-bound delta proposal, still `NOT_APPLIED` and `execution_authorized=false`.

## Deliberate exclusions

R43 is claims-only. It does not create or supersede decisions, does not issue HUMAN/CONTROLLER authorization, and does not invoke R37 apply. Terminal decisions remain a separate authority path.

No canonical-state mutation, deployment, agent dispatch, external messaging, trading, wallet access or capital permission is added.
