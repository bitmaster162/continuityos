# Anti-Amnesia semantic close v1.1

`continuity close` keeps the existing v1 shadow validator unchanged.  Supplying
both `--work-order` and `--permission-policy` selects the v1.1 semantic close:

```text
continuity close \
  --return RESULT.zip \
  --dry-run \
  --work-order WORK_ORDER.md \
  --permission-policy ROLE_PERMISSIONS.json \
  --control-root <R63-current-root> \
  --workspace-root <ContinuityOS-runtime-root>
```

The command is deterministic and non-applying.  It never mutates R63, runtime
state, checkpoints, Git repositories, the return registry, or external systems.

## Trusted inputs

The controller, not the agent, selects:

- the current R63 control root;
- the current ContinuityOS workspace root;
- the exact work-order body;
- the role permission policy.

The return candidate must declare SHA-256 bindings for the work-order body,
permission policy, base state, physical boot receipt, artifacts, and Git bundle.

## V1.1 checks

The validator verifies:

1. the physical boot receipt is current and exactly reproducible;
2. the explicit base-state SHA derived from authority, workspace, role, and case;
3. the exact work-order body SHA;
4. the exact permission-policy SHA;
5. structured JSON-Pointer deltas against role-specific prefixes;
6. global immutable/authority paths remain forbidden;
7. Git bundle integrity, final branch, baseline ancestry, commit/tree identities,
   exact changed-path inventory, and role-specific Git scope;
8. every test evidence reference exists in the artifact inventory;
9. test result/tally coherence;
10. compensatable, irreversible, or externally effective requests route to
    `PENDING_HUMAN_APPROVAL`.

## Outcomes

```text
WOULD_ACCEPT
WOULD_ACCEPT_WITH_WARNINGS
PENDING_HUMAN_APPROVAL
WOULD_HOLD
```

All results remain shadow-only:

```text
closed=false
enforced=false
live_state_modified=false
writes_performed=[]
can_trade=false
capital_permission=DENY
```

## Permission policy

A policy is bound to one authority generation and defines per-role:

- whether role-only work without a case is permitted;
- allowed JSON-Pointer delta prefixes;
- allowed Git paths or path prefixes;
- allowed effect classes.

A path ending in `/` is a Git prefix.  Other Git paths are exact.  The permission
policy is selected by the controller and its SHA is declared by the return; an
agent cannot authorize itself by embedding a different policy in its ZIP.

See `examples/anti_amnesia_role_permission_policy_v1.json`.

## Deliberate limits

V1.1 does **not**:

- apply the proposed delta;
- update `CURRENT_POINTER.json`;
- grant production, credential, external-message, trading, or capital authority;
- prove the cleanliness of the agent's original working directory from a Git
  bundle alone;
- replace independent host-side test or deployment receipts.

Atomic apply, rollback/compensation, and provider-readback integration remain
separate future gates.
