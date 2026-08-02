# GitHub Control-Plane Integration v1

This integration branch closes the accidental sibling-branch split after
`gpt/github-work-admission-gate-v1.1` by composing three independently validated
candidate lines into one linear Git history:

1. **Work Validation Evidence Gate v1** — executes exact admitted argv without a
   shell, captures bounded raw stdout/stderr outside the repository, and verifies
   the evidence independently.
2. **GitHub Work Ledger v1.1** — records the admitted work lifecycle as immutable,
   canonical JSONL successors bound to exact receipt bytes and Git identities.
3. **GitHub Candidate Review Gate v1** — binds admission, delta, authenticated
   transport, exact-head CI, secret-scan evidence and GPT semantic review before
   emitting proposal-only merge eligibility.

The resulting control flow is:

```text
exact task + session capsule + Git baseline
                    ↓
          WORK_ADMISSION_PASS
                    ↓
    exact argv execution + raw evidence
                    ↓
 WORK_VALIDATION_EXECUTION_PASS
                    ↓
  WORK_VALIDATION_EVIDENCE_PASS
                    ↓
           WORK_DELTA_PASS
                    ↓
 immutable work-ledger successors
                    ↓
 authenticated remote readback + CI
                    ↓
 exact GPT semantic review decision
                    ↓
 GITHUB_CANDIDATE_REVIEW_PASS
                    ↓
      MERGE_CANDIDATE_ELIGIBLE
```

`MERGE_CANDIDATE_ELIGIBLE` is proposal-only. This branch does not add a merge,
auto-merge, deployment, current-state apply, R63 apply, registry apply, wallet,
order or trading path.

## Integration authority

```text
accepted authority generation  R63
accepted technical parent      gpt/github-work-admission-gate-v1.1
integration branch              gpt/github-control-plane-integration-v1
force push                      false
merge executed                  false
deployment                      false
can_trade                       false
capital_permission              DENY
deploy_permission               DENY
self_application                false
```

## Why integration precedes the merge-authorization gate

The three features were created as sibling branches from one accepted parent.
Building the next gate on any single sibling would silently omit the other two.
This branch establishes one tested, linear foundation. A later merge-authorization
candidate must use this integration HEAD/tree as its exact parent.
