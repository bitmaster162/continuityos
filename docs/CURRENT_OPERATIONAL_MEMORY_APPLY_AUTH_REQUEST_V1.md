# Current Operational Memory Apply Authorization Request v1 (R45)

R45 removes manual copying of exact R36 proposal/base fields before a HUMAN or DETERMINISTIC_CONTROLLER reviews a possible R37 shadow-memory apply.

## Command

```text
continuity-memory-apply-auth-request \
  --operational-db PROJECT.db \
  --proposal DELTA_PROPOSAL.json
```

The command requires a verified current R64 session and is read-only.

## Output

For a structurally valid proposal whose exact base still matches the immutable OperationalMemory snapshot, R45 emits:

- exact `proposal_id` and proposal-file SHA-256;
- project ID;
- exact projection/cursor/chain/current-work base;
- operation count;
- the R37 authorization schema and approval value **if an authority later chooses to approve**;
- an intentionally incomplete `authorization_skeleton`.

The skeleton pre-fills only deterministic proposal/base bindings. These fields remain `null` and require a separate authority action:

- `decision`;
- `authority_class`;
- `authority_id`;
- `authority_ref`;
- `apply_recorded_at`;
- `rationale`.

The emitted skeleton is deliberately **not valid R37 authorization**. Tests lock this invariant by requiring R37 `_validate_authorization` to reject the untouched skeleton.

## Required continuation

If an authorized HUMAN or DETERMINISTIC_CONTROLLER independently decides to approve and creates a complete authorization artifact, run R44 `continuity-memory-apply-check` against that exact artifact. `READY` is still point-in-time only. The separate unbound R37 apply gate must re-read and revalidate all inputs under its write lock.

R45 never grants or authenticates authority, writes OperationalMemory, creates an authorization artifact, mutates canonical state, deploys, dispatches agents, trades, accesses wallets, or grants capital permission.
