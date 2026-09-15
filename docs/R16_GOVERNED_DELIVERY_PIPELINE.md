# R16 Governed Delivery Pipeline

Status: candidate / source-and-test only

Normative parent: `CORE_V6_4_GOVERNED_DELIVERY_RC1`, extending CORE v6.3.4 RC2.

Exact starting protected baseline for this R16 candidate:

- repository: `bitmaster162/continuityos`
- master commit: `ac6e976dedd6a6c106c1d11db26e42935d0a0159`
- master tree: `83401a6f91978bfec25175fc4a21b93e69e85323`

## Purpose

R16 makes the software-delivery control flow explicit and machine-checkable without expanding execution authority:

`PLAN -> CODE -> TEST -> REVIEW -> HUMAN_MERGE_GATE_REQUEST`

The first slice is a deterministic receipt/validator layer only. It does not execute commands, call providers, access the network, mutate files at runtime, merge a pull request, deploy software, provision hardware, handle secrets, trade, or move capital.

## Stage guarantees

### PLAN

Binds the work order generation, repository, exact baseline commit/tree, scope digest, acceptance-test digest, parity specification, effect ceiling, actor identity, route identity and nonce.

### CODE

Requires a valid PLAN receipt and a distinct coder session. Binds exact candidate commit/tree and diff digest. One-writer remains a higher-level physical worktree invariant.

### TEST

Requires a valid CODE receipt and a distinct tester session. Tests must pass. Behavior-preserving work requires `PARITY_PASS` and no observed-delta digest. An intentional behavior change requires `EXPECTED_DELTA_PASS` plus an `observed_delta_sha256` that exactly equals the plan-bound `expected_delta_sha256`.

### REVIEW

Requires a valid TEST receipt and a distinct reviewer session. The first R16 slice emits merge-eligible review evidence only for `PASS`. `REVISE` and `REJECT` fail closed.

### HUMAN_MERGE_GATE_REQUEST

Requires REVIEW PASS plus fresh exact base/head/tree equality. This pure layer emits only an exact-candidate request for a separate trusted Human approval boundary. It does not accept `human_id`, raw approval tokens, token digests, or caller-supplied approval booleans.

The request produces `AWAITING_HUMAN_MERGE_GATE`, always preserves `can_merge=false`, and records whether an intentional behavior delta requires explicit Human approval. Actual merge eligibility must be minted by a later authenticated Human-approval boundary that is outside this R16 slice.

## Identity boundary

Machine actor identity binds:

- provider
- declared model ID
- attested runtime model ID
- session ID
- route ID

Declared and caller-supplied runtime model IDs must match. This pure slice does not cryptographically attest model runtime identity; a future trusted attestation boundary must bind that evidence. Planner, coder, tester and reviewer session IDs must be distinct, but this slice does not prove that those session IDs came from different physical operators.

## Drift behavior

Receipts are content-addressed with SHA-256 over canonical JSON. This detects unresealed mutation but is not an authenticity signature: a future trust boundary must provide authenticated custody before treating receipts as cross-boundary evidence. The Human gate request fails if baseline commit, candidate commit or candidate tree differs from the reviewed values. `require_human_merge_gate_request_current` repeats the exact-revision check immediately before handoff to the separately implemented trusted Human approval boundary.

Any future integration that changes work-order generation, policy version, scope, acceptance tests, parity contract, candidate bytes, actor/session identity, route, or effect ceiling must invalidate downstream receipts and restart from the earliest affected stage.

## Authority boundary

All receipts preserve:

- `execution_authority=NONE`
- `can_execute=false`
- `deploy_permission=DENY`
- `can_trade=false`
- `capital_permission=DENY`

All stages in this R16 slice preserve `can_merge=false`.

No function in this module can mint Human approval or merge authority. A future trusted approval boundary must authenticate the Human decision and re-bind it to the exact request/base/head/tree before any merge can become eligible.

## Acceptance targets for this slice

- deterministic receipt IDs
- receipt tamper detection
- strict stage ordering
- model/runtime identity mismatch rejection
- planner/coder/tester/reviewer session separation
- test failure rejection
- parity mismatch rejection
- intentional-delta Human-approval requirement is carried forward as an explicit external-gate requirement
- review PASS requirement
- base/head/tree drift rejection before and after Human gate
- no Human approval minting surface; no human ID/token/token-digest inputs in this pure layer
- stdlib-only capability surface
- existing no-execution/no-deploy/no-trading/no-capital defaults preserved

## Non-goals

R16 R1 does not wire this state machine into GateBroker, MCP execution, GitHub merge APIs, CI orchestration, TPM custody, deployment or release automation. It also intentionally does not implement authenticated Human approval. Those integrations require their own exact-candidate review and authority gates after this pure layer passes natural CI and independent review.

## Trust notes

`attempt_nonce` is receipt-bound entropy supplied by the caller; this pure slice does not maintain a replay registry. Cross-boundary replay prevention and authenticated receipt custody belong to the future trusted approval/attestation boundary. Human-gate requests carry test-suite, parity, observed-delta and review evidence and revalidate those invariants before handoff.
