# Merge Execution Receipt Gate v2 (R22)

R22 makes the R20 dual-control handoff mandatory evidence for merge-execution verification. The gate remains read-only: it never calls GitHub, executes a merge, deploys, mutates Git or ContinuityOS state, trades, accesses wallets, or grants capital authority.

A v2 request must hash-bind `DUAL_CONTROL_MERGE_HANDOFF_READY`. The evaluator revalidates that handoff as current using an external trusted Human key registry and an operator-supplied pinned registry SHA-256. The R63 authorization is pinned by canonical JSON SHA-256 and must match the handoff exactly.

The same `dual_control_handoff_sha256` must also appear in the v2 host execution receipt and v2 authorization-consumption receipt. Therefore `MERGE_EXECUTION_VERIFIED` cannot be produced from an execution bundle that omits or substitutes the R20 handoff.

Required identity remains exact: repository, base branch/head/tree, candidate branch/head/tree, pull-request number, and `MERGE_COMMIT`. R20 remains `VERIFY_ONLY_NO_MERGE`; R63 remains one-time until consumption. R22 adds no executor and no merge authority.

Active v2 terminals remain:

```text
MERGE_EXECUTION_VERIFIED / MERGE_RESULT_PROVEN
MERGE_EXECUTION_HOLD / WOULD_HOLD
MERGE_EXECUTION_REVISE / WOULD_HOLD
```

Missing required artifacts are HOLD. Tampering, stale R19 eligibility inside the handoff, trust-registry pin mismatch, identity drift, handoff substitution, reused authorization, wrong parents, weakened protection, visibility drift, or widened effects are REVISE.

Historical v1 schemas remain packaged for auditability, but the active evaluator accepts only v2 request/host/consumption contracts.
