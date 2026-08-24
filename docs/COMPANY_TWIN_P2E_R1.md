# Company Twin P2E-R1 — Public GitHub self-pilot

Status: implementation candidate.
Base protected master: `0429ea2ea836b0fcbcc390ebecb4d7e8fc02ed05`
Work order: Issue #133.
Boundary: **PUBLIC_GITHUB_ONLY / NO_MERGE / NO_DEPLOY / NO_RUNTIME**.

## Objective
P2E-R1 is the first Company Twin pilot that uses real ContinuityOS history rather than a synthetic company narrative.

The pilot consumes a pinned, public-only evidence set from `bitmaster162/continuityos` and routes it through:

`public GitHub evidence -> P2B ingestion -> P2A temporal memory -> P2C policy -> P2D Operating Console`

It does not perform authenticated or live GitHub calls at package import, test, or runtime.

## Pinned real history
- Issue #123
- PR #124 + merge `72f3811c...` P2A
- PR #128 + merge `a3bcc608...` P2C
- P2D review-gates run `32681056154` on `d85c95d6...` = failure
- P2D review-gates run `32681315315` on `8df3c0d6...` = success
- PR #132 + merge `0429ea2e...` P2D

The failed and successful workflow artifacts are separate source evidence. The process observation is evidence-backed, not model inference.

## Source boundary
Only `issue`, `pull_request`, `commit`, and `workflow_run` artifacts are accepted.

Each artifact type has an explicit payload allowlist. Unknown non-sensitive fields are discarded. Secret-like fields, non-public artifacts, repository mismatches, malformed timestamps, unsupported types, and non-public raw references fail closed. Arbitrary GitHub response objects are never forwarded into Company Twin memory.

## Truth model
- imported GitHub objects -> `EVIDENCE`
- GitHub-recorded completed workflow / commit / merge facts -> `FACT`
- no automatic model inference

Merged PR rationale is deliberately narrow:

> GitHub records this pull request as merged; no additional rationale is inferred.

## Organizational scope
This pilot history is placed in `team:engineering`.

- Director can inspect it.
- Engineering Worker can inspect it.
- Research Robot can inspect/propose under bounded delegation.
- Operations Worker does not gain engineering-history visibility.
- `EXECUTE` remains absent/denied.

## Replay
Pinned acceptance cutoffs:

- `2026-08-24T00:30:00Z` -> P2A only
- `2026-08-24T01:30:00Z` -> P2A + P2C
- `2026-08-24T03:00:00Z` -> P2A + P2C + P2D plus the P2D failure-to-success qualification sequence

## Idempotency
The same pinned history re-ingests without duplicate canonical records. Input ordering is normalized before envelope construction.

## Explicit non-goals
- no merge without a separate exact-head approval
- no deploy or local install/start
- no Gmail, Drive, Slack, customer data, private repositories, or OAuth
- no R21H runtime, canonical-memory, admissions, or model mutation
- no robot execution
- no trading or capital authority
