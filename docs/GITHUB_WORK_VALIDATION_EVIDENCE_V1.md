# GitHub Work Validation Evidence Gate v1

The evidence gate closes the gap between a validation receipt that merely
*claims* stdout/stderr hashes and the raw bytes actually produced by the exact
admitted command vectors.

## Lifecycle

### 1. Admit the work

```text
continuity work-admission verify \
  --request WORK_ADMISSION_REQUEST.json \
  --work-order WORK_ORDER.md \
  --session-capsule SESSION_CAPSULE.json \
  --repo <exact clean base clone>
```

The request should set:

```json
{
  "validation": {
    "raw_evidence_required": true,
    "continue_on_failure": false,
    "max_total_output_bytes": 67108864
  }
}
```

Each required command can additionally bind:

```json
{
  "id": "focused",
  "argv": ["python", "-m", "pytest", "-q", "tests/test_feature.py"],
  "cwd": "repo",
  "kind": "FOCUSED",
  "timeout_seconds": 900,
  "max_stdout_bytes": 8388608,
  "max_stderr_bytes": 8388608
}
```

The command remains argv-only. Shell carriers, shell syntax and PowerShell
`-Command`/`-EncodedCommand` remain denied by the admission gate.

### 2. Commit the candidate

The executor performs only the admitted change and creates a clean candidate
commit on the admitted candidate branch.

### 3. Execute exact validation commands

```text
continuity work-admission run-validation \
  --admission-receipt WORK_ADMISSION_RECEIPT.json \
  --admission-receipt-sha256 <SHA256> \
  --repo <candidate repo> \
  --output-dir <absolute empty directory outside repo>
```

The runner:

- revalidates the admission receipt and exact candidate Git identity;
- executes only the admitted argv/cwd vectors;
- never invokes a shell;
- refuses direct network utilities, Git transport commands and dependency-install
  commands; those require separate authenticated transport/setup gates;
- writes stdout and stderr as raw binary files;
- enforces per-command timeout and output budgets;
- stops safely on failure unless `continue_on_failure=true` was admitted;
- verifies that branch, HEAD, tree and worktree stayed unchanged;
- writes an exact manifest and READY marker.

Output:

```text
WORK_VALIDATION_RECEIPT.json
NO_EFFECT_RECEIPT.json
MANIFEST.json
READY_FOR_VERIFY.json
raw/<command-id>.stdout.bin
raw/<command-id>.stderr.bin
```

The evidence directory must be outside the Git repository. It is evidence, not
source, and must not be committed to GitHub.

### 4. Independently verify evidence

```text
continuity work-admission verify-validation \
  --admission-receipt WORK_ADMISSION_RECEIPT.json \
  --admission-receipt-sha256 <SHA256> \
  --repo <candidate repo> \
  --evidence-dir <evidence directory>
```

A pass proves:

- admission receipt bytes and binding SHA are exact;
- candidate branch/HEAD/tree remain exact and clean;
- manifest covers every evidence file exactly;
- READY binds the manifest and validation receipt;
- every raw stdout/stderr file has the exact size and SHA recorded in the
  command receipt;
- no command failed, timed out, exceeded output limits or was truncated;
- no dangerous effect or authority widening was recorded.

Terminal statuses:

```text
WORK_VALIDATION_EVIDENCE_PASS
WORK_VALIDATION_EVIDENCE_HOLD
WORK_VALIDATION_EVIDENCE_REVISE
```

### 5. Verify the candidate delta

```text
continuity work-admission verify-delta \
  --admission-receipt WORK_ADMISSION_RECEIPT.json \
  --admission-receipt-sha256 <SHA256> \
  --validation-receipt <evidence-dir>/WORK_VALIDATION_RECEIPT.json \
  --validation-evidence-dir <evidence-dir> \
  --repo <candidate repo>
```

When `raw_evidence_required=true`, the delta cannot pass without independently
verified raw evidence.

## What this proves

The gate proves that the admitted commands produced the exact captured bytes on
the exact candidate commit and that the repository remained clean.

It does **not** prove:

- semantic correctness of the feature;
- absence of every possible indirect network access inside arbitrary test code
  (direct network/install argv are denied, but this is not an OS network sandbox);
- suitability for merge or deployment;
- authority/state promotion.

Those remain separate review, transport and promotion gates.

## Effects

The only admitted effects are:

- execution of exact test/build/static-analysis argv;
- writing evidence to the declared external evidence directory.

The gate has no push, merge, PR, deployment, registry, R63, wallet, order,
trading or capital path.

## Disposable-workspace requirement

When `raw_evidence_required=true`, the admission request must use
`workspace.mode=DISPOSABLE_CLONE_REQUIRED`.  The base clone, candidate clone and
external evidence directory must all resolve under the admitted host prefixes,
while the evidence directory must remain outside the Git repository.  This
bounds a defective validation command to a disposable workspace; a fail-closed
receipt is not treated as rollback for a live source root.

Output budgets are enforced while pipes are drained.  The runner never redirects
an unbounded producer directly to disk and then checks file size afterward.
