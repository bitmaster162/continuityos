# CM_CONNECTION_RUNBOOK_R1 — day-of-connection checklist

Status: HOLD / EVIDENCE ONLY. This document grants no authority to connect a client.

## Preconditions (all required)
- Owner explicitly approves a separate connection change, with exact client identity, principal, scope, data classification, lifetime and revocation.
- Git baseline/HEAD, clean working tree, and both draft security reviews independently verified. No merge occurs as part of this runbook.
- Independently attest the source and freshness of the Central Memory release. R6.1 is an offline snapshot with agent_access=DENY and effect_authority=NONE: do not attempt a connection while either remains DENY/NONE.
- Complete least-privilege threat review, safe data classification, no credentials or private sources, path containment, audit requirements, replay and negative tests.
- Verify absence of exposed delete paths. Legacy MCP forget is independently protected; an adapter alone is not protection for other endpoints.
- Establish a reliable disconnect/kill switch and a separately tested rollback strategy before authorizing any connection.

## Connection-day sequence (future approval only)
1. Obtain fresh readback of release manifest, hashes, actual local filesystem view and runtime configuration. Record UTC, reviewer and provenance.
2. Re-run isolated unit/integration, all CI and negative-tool-list tests; require no secret or destructive tool exposure.
3. Confirm owner signature/authority using a separate trusted channel. Bind approval to specific client, permitted tools, exact data projection and expiry.
4. Stage one synthetic-client read-only session (not canonical DB), verify tool list and no side effects; never auto-promote.
5. Only after a NEW explicit owner decision, connect one allowed client at a time with strict scopes; verify readback and record audit receipt.
6. Check outbound data, unintended writes, deletion attempts, authority escalation, and revocation effect. Fail closed on any ambiguity.
7. Verify monitoring, stop control, access expiration and immediate disconnection. Issue post-connection receipt and owner review.

## Rollback / STOP
Stop before connection for missing authorization, stale evidence, changed source hash, unexpected tool, failed CI, secret exposure, side effects or inability to revoke. Disconnect client and revoke its distinct capability; this does not roll back prior disclosures. Keep canonical memory and owner credentials unchanged.

## COS-R3 status
No client connections, no production admission and no server or key changes are authorized by PR #217 or #218.

## Independent Central Memory line runbook reconciliation (R3)
The private owner-side runbook on the laptop additionally requires per-client identity, expiry,
revocation, metadata-only read journal, independently reviewed R6.2 projection,
and denied unauthenticated/expired/revoked/overscoped access tests.
This R3 adapter is deliberately a *status-only offline DENY probe* and implements
NONE of those client-admission capabilities. Its green CI is NOT connection readiness.
The 16-line LINES_REGISTRY_CURRENT source is not part of R6.1 agent_view and
must not be copied into that projection without a separate signed owner decision.

For an EVIDENCE_ONLY reconciliation, first obtain a fresh owner-authorized bounded
read-only **runtime line-registry export** with 16 stable IDs and the agreed seven
fields, a source/version timestamp and provenance receipt. Compare against the current
canonical LINES_REGISTRY_CURRENT source offline; issue field-level differences,
missing/extra IDs and stale records. Do not query the owner SQLite or authenticated
gateway using this runbook. Without this export, mark runtime reconciliation INCOMPLETE.
