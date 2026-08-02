# GitHub Work Admission Gate v1

The gate prevents an agent from starting or completing persistent GitHub work
without an exact task, session, Git and scope binding.

## Before work

```text
continuity work-admission verify \
  --request WORK_ADMISSION_REQUEST.json \
  --work-order WORK_ORDER.md \
  --session-capsule SESSION_CAPSULE.json \
  --repo <clean exact Git root> \
  --check-remote
```

A pass proves:

- R63 remains the authority generation;
- the work-order and session-capsule bytes match their declared SHA-256;
- the capsule binds role, task, repository, scope and effect ceiling;
- branch, HEAD, tree, remote and clean status match the request;
- the candidate branch is separate from base/default branches;
- allowed paths and resource limits are explicit;
- force push, merge, deployment, R63/current-state/registry apply, trading,
  wallet/order access and self-application are denied;
- the remote base and candidate-branch state are exact when required.

The receipt is effect-free and returns one status:

- `WORK_ADMISSION_PASS`
- `WORK_ADMISSION_HOLD`
- `WORK_ADMISSION_REVISE`

## After work

The executor records required test commands in a validation receipt and runs:

```text
continuity work-admission verify-delta \
  --admission-receipt WORK_ADMISSION_RECEIPT.json \
  --admission-receipt-sha256 <SHA256> \
  --validation-receipt WORK_VALIDATION_RECEIPT.json \
  --repo <candidate Git root> \
  --check-remote
```

The delta gate verifies:

- candidate branch and linear ancestry from the exact admitted base;
- no merge commits and a clean worktree;
- every changed path is admitted and no protected content is introduced;
- changed-file, byte and commit budgets;
- new-file/deletion/binary/workflow permissions;
- test receipts bound to the exact candidate HEAD/tree and admission SHA;
- no dangerous effect or remote-branch conflict.

Even `WORK_DELTA_PASS` permits only a later candidate-transport step.  It does
not push, merge, deploy, modify R63/current state, or trade.
