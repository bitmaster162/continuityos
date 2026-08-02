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
- the repository is the exact Git top-level, is not a symlink, passes
  `git fsck --full --strict`, and has no merge/rebase/cherry-pick in progress;
- optional disposable-workspace allow/deny roots are enforced;
- local and remote candidate-branch state match the admission request;
- the candidate branch is separate from base/default branches;
- allowed paths and resource limits are explicit; path components are checked for
  POSIX traversal plus Windows-reserved/invalid names;
- force push, merge, deployment, R63/current-state/registry apply, trading,
  wallet/order access and self-application are denied;
- the remote base and candidate-branch state are exact when required;
- JSON/work-order inputs and validation command vectors are bounded; shell
  carriers and embedded shell syntax are rejected, while PowerShell is allowed
  only through `-File`.

The request's `PRIVATE`/`PUBLIC` value is a policy assertion bound into the
receipt. Local Git and `git ls-remote` cannot independently prove GitHub
visibility; actual visibility must be supplied by the later authenticated GitHub
transition/readback receipt.

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
- changed-file, positive-byte and commit budgets;
- no unmerged/type changes, symlinks, submodules, protected credentials, raw
  chat exports, runtime databases or archive payloads unless explicitly allowed;
- `git diff --check` and Git integrity remain clean;
- new-file/deletion/binary/workflow permissions;
- test receipts bound to the exact candidate HEAD/tree, admission receipt and
  binding SHA; required argv/cwd are exact, unadmitted commands are rejected,
  and network/install/full-suite budgets cannot widen;
- no dangerous effect or remote-branch conflict.

When the request sets `validation.raw_evidence_required=true`, the lifecycle
must include:

```text
continuity work-admission run-validation ...
continuity work-admission verify-validation ...
continuity work-admission verify-delta --validation-evidence-dir ...
```

The raw-evidence gate rehashes the actual stdout/stderr bytes and prevents a
fabricated validation receipt from satisfying the delta gate. See
`GITHUB_WORK_VALIDATION_EVIDENCE_V1.md`.

Even `WORK_DELTA_PASS` permits only a later candidate-transport step.  It does
not push, merge, deploy, modify R63/current state, or trade.
