# Merge Execution Receipt Gate v1

The gate verifies one merge that was already executed by an external GitHub/host path.
It never calls GitHub and cannot mutate Git, merge, deploy, apply R63/current state/registry,
activate memory, access wallets, execute orders, or trade.

A verified result requires exact binding to:

- `MERGE_AUTHORIZATION_PASS / MERGE_EXECUTION_MAY_BE_REQUESTED_ONCE`;
- one authorization subject SHA and one bounded nonce;
- one host execution receipt;
- one GitHub PR readback showing `MERGED`;
- one independent merge-commit readback with exact tree and ordered parents;
- one base-branch readback pointing to that merge commit/tree;
- one post-merge branch-protection readback preserving checks, approvals, visibility,
  force-push denial, and branch-deletion denial;
- one authorization-consumption receipt with `use_count=1` and `reused=false`.

Version 1 supports only a transparent two-parent `MERGE_COMMIT`:

```text
parents[0] = exact base HEAD before merge
parents[1] = exact candidate HEAD
```

Terminals:

```text
MERGE_EXECUTION_VERIFIED / MERGE_RESULT_PROVEN
MERGE_EXECUTION_HOLD / WOULD_HOLD
MERGE_EXECUTION_REVISE / WOULD_HOLD
```

`HOLD` is reserved for physically incomplete provider/readback state. Contradictory,
tampered, widened, reused, stale-subject, wrong-parent, force-push, auto-merge,
visibility-drift, deployment, state-apply, wallet, order, or trading evidence is `REVISE`.

A verified merge result still does **not** imply deployment, current-truth promotion,
memory activation, or semantic acceptance.
