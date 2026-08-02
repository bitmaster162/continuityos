# GitHub Candidate Review Gate v1

The review gate closes the GitHub candidate lifecycle without granting merge or
deployment authority.

```text
exact task + session capsule
        ↓
WORK_ADMISSION_PASS
        ↓
committed candidate + exact validation
        ↓
WORK_DELTA_PASS
        ↓
exact remote branch + CI + secret scan
        ↓
exact semantic review decision
        ↓
GITHUB_CANDIDATE_REVIEW_PASS
        ↓
MERGE_CANDIDATE_ELIGIBLE
```

`MERGE_CANDIDATE_ELIGIBLE` is a proposal-only terminal. It does not merge a
branch, enable auto-merge, create a deployment, apply R63/current state, or
record human approval.

## Evaluate

```text
continuity github-review evaluate \
  --request GITHUB_CANDIDATE_REVIEW_REQUEST.json \
  --admission-receipt WORK_ADMISSION_RECEIPT.json \
  --delta-receipt WORK_DELTA_RECEIPT.json \
  --transport-receipt GITHUB_CANDIDATE_TRANSPORT_RECEIPT.json \
  --semantic-decision GITHUB_CANDIDATE_SEMANTIC_DECISION.json
```

The evaluator returns exactly one status:

- `GITHUB_CANDIDATE_REVIEW_PASS`
- `GITHUB_CANDIDATE_REVIEW_HOLD`
- `GITHUB_CANDIDATE_REVIEW_REVISE`

## PASS requirements

A PASS binds all of the following to exact bytes and Git identities:

- work-order SHA and session-capsule SHA;
- `WORK_ADMISSION_PASS` receipt and its internal binding SHA;
- `WORK_DELTA_PASS` receipt and exact candidate HEAD/tree;
- GitHub repository, visibility, base branch, candidate branch and remote
  candidate HEAD/tree;
- a clean secret/raw-evidence scan bound to the exact candidate HEAD;
- every required GitHub Actions workflow, completed successfully on the exact
  candidate HEAD;
- one exact semantic review decision bound to the request, admission, delta and
  transport receipt SHA-256 values;
- review role/mode and optional executor/reviewer separation;
- no unresolved P0/P1 finding;
- no force push, merge, auto-merge, deployment, registry/current-state/R63 apply,
  wallet/order/trading or self-application effect.

## HOLD conditions

HOLD is used for a valid but non-terminal state:

- the remote base branch advanced after the admitted base HEAD/tree;
- a required workflow receipt is missing or still running;
- a required pull request has not yet been created;
- the semantic reviewer explicitly returned `HOLD`.

Base drift requires a new Work Admission from the new base. The review gate does
not silently rebase or reinterpret the old admission.

## REVISE conditions

REVISE is used for material defects:

- receipt SHA or task/session/Git binding mismatch;
- delta did not pass;
- local/remote candidate HEAD/tree mismatch;
- failed CI or CI attached to a different HEAD;
- secret/raw-evidence leakage;
- force push, merge, auto-merge or deployment;
- visibility change;
- review self-separation violation;
- unresolved P0/P1 findings;
- an invalid or already merged pull request;
- semantic `REVISE` or `REJECT`.

## Pull requests

Pull-request evidence is optional and must be explicitly admitted. When present,
the gate requires exact base/head branches, exact candidate HEAD, `OPEN` state,
`merged=false`, `auto_merge_enabled=false`, and optionally `draft=true`.

The gate never calls GitHub and never creates or merges a pull request. The
transport receipt must come from an authenticated host or GitHub integration.

## Authority

```text
authority_generation      R63
human_irreversible_approval false
merge_executed             false
can_trade                   false
capital_permission          DENY
deploy_permission           DENY
self_application            false
```
