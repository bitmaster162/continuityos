# Merge Authorization Gate v1

A one-time, proposal-only authorization for one exact GitHub merge candidate.
It requires:

- Work Ledger ↔ Candidate Review binding PASS;
- Candidate Review PASS / `MERGE_CANDIDATE_ELIGIBLE`;
- exact branch-protection readback;
- exact open, non-draft, unmerged pull request;
- all required checks successful on the exact candidate HEAD;
- independent approval threshold;
- tested non-destructive `REVERT_MERGE_COMMIT` rollback;
- one bounded, unexpired and unused Robert decision bound to an exact subject
  SHA and nonce.

Only transparent `MERGE_COMMIT` is supported in v1. A PASS emits
`MERGE_EXECUTION_MAY_BE_REQUESTED_ONCE`; the gate cannot execute the merge.

## Installed-wheel policy

The machine-readable authorization ceiling is shipped as
`continuityos.control_plane_policy/merge_authorization_policy_v1.json`.  The
packaged resource and source document are cross-checked without weakening the
rule that the gate cannot execute the merge.
