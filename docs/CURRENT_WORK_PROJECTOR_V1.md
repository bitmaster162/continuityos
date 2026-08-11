# Current Work Projector v1 (R35)

`continuity-work` turns one existing Common Operational Memory project into a compact, deterministic, read-only operator capsule.

It is the first product layer that uses the verified current-session memory for an operational question: **what is this project doing now, what is blocking it, and what is the next recorded action?**

## Preconditions

The command requires an already verified current-session binding in the environment:

- `CONTINUITYOS_CURRENT_CHALLENGE`
- `CONTINUITYOS_CURRENT_CHALLENGE_SHA256`
- `CONTINUITYOS_CURRENT_ACK`
- `CONTINUITYOS_CURRENT_SESSION_REQUIRED=1`

Use `continuity current-env` to produce these bindings from an exact verified challenge/ACK pair.

The command also requires an existing Common Operational Memory v1 SQLite database. A missing path is REVISE and is never created by `continuity-work`.

## Command

```text
continuity-work \
  --project project:continuityos \
  --operational-db /path/to/common_operational_memory_v1.db
```

The project argument is the exact `subject_id` used by OperationalMemory claims and decisions.

## Project predicates

R35 recognizes these current project claims:

- `project.goal` — one `global` claim;
- `project.status` — one `global` claim;
- `project.open_loop` — multiple claims, differentiated by `scope`;
- `project.blocker` — multiple claims, differentiated by `scope`;
- `project.next_action` — multiple candidate actions, differentiated by `scope`.

Unknown predicates are left untouched and are not interpreted by this projector.

An open-loop value is an object such as:

```json
{
  "id": "r35",
  "title": "Build current-work projector",
  "status": "OPEN",
  "next_action": "run review-gates",
  "priority": 80,
  "blocked_by": []
}
```

A blocker can be a string or an object:

```json
{
  "id": "ci",
  "title": "Windows CI is red",
  "status": "OPEN",
  "severity": 90,
  "blocks": ["r35"]
}
```

A `project.next_action` value can be a string or an object containing `action`, optional `id`, `priority`, `blocked_by`, and `owner`.

## Decision precedence

The projector never lets a claim outrank an accepted decision.

1. Exactly one current `NEXT_ACTION` decision in `ACCEPTED` state selects that action.
2. A current `NEXT_ACTION` decision in `HOLD` or `REJECTED` state holds the project.
3. Multiple current terminal `NEXT_ACTION` decisions are a memory conflict and return REVISE.
4. If there is no terminal decision, `PROPOSED` decisions, `project.next_action` claims, and open-loop next actions are candidate proposals only.
5. Active blockers may hold an accepted action or remove proposed candidates. Blockers never grant authority.

A proposed candidate is selected deterministically by priority, source class, evidence rank, and stable source identity. It remains explicitly non-authoritative and requires a decision.

## Output ceilings

A successful capsule may identify the next operational action, but it never authorizes execution:

- `execution_decision=HOLD`
- `execution_authorized=false`
- `agent_dispatch=false`
- `deployment=false`
- `current_state_apply=false`
- `canonical_mutation=false`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

The Common Operational Memory remains shadow-only; Control Center remains the accepted-truth owner.

## Failure behavior

Malformed recognized project claims, conflicting current singleton facts, conflicting terminal `NEXT_ACTION` decisions, an invalid OperationalMemory database, or an invalid/missing current-session binding all fail closed.

R35 performs no automatic memory write, decision creation, task dispatch, merge, deployment, external message, trading action, wallet access, or capital action.
