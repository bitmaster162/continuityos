# RUAP R3 — 16-line reconciliation (EVIDENCE_ONLY)

Reference: LINES_REGISTRY_CURRENT R4/R6.2 (16 lines, Google Drive source).
Runtime source: NOT AVAILABLE TO AGENT. R6.1 agent_view contains 10 offline policy rules, not these 16 lines; access is DENY.

## Current discrepancy
- Evidence gap: 16 of 16 reference line IDs are not exposed by the allowed status-only adapter.
- This does NOT prove records are missing from canonical ContinuityOS storage.
- No authorized runtime registry export with an independently verifiable provenance receipt has been supplied.
- R6.1 policy snapshot is stale relative to R6.2 and must not be silently updated or promoted.

## Safe offline tool (without any runtime call)
`python -m tools.ruap_lines_evidence_compare_r3 --reference <approved-reference-export.json> --runtime <approved-runtime-export.json>`

Each JSON export has schema `continuityos.ruap_lines_evidence/v1`, `source_version` string,
and `records` containing a stable integer `id` and seven string fields:
`line`, `executor_chat`, `bucket`, `current_state`, `next_turn`, `evidence`, `updated_at`.
The reference export must contain IDs 1..16 exactly. Input files must be regular files of
at most 128 KiB each. All output omits field values; it reports IDs, differing field names,
source-version mismatch, counts and a non-authoritative status.

The utility never opens SQLite, reads the owner gateway, writes to disk, loads a capability,
contacts a client or promotes memory. Exact matching fields produce `FIELD_MATCH_UNATTESTED`,
**not COMPLETE**. Source provenance must be verified by an independent owner-side reviewer.

## Required to reach COMPLETE
Obtain a scoped, owner-authorized, sanitized **read-only runtime registry export** (all 16
stable IDs, seven agreed fields, source version and provenance/attestation receipt); obtain
a matching fresh R6.2 LINES_REGISTRY_CURRENT reference export with verified metadata.
Run offline comparison, independently verify the export/receipts and report field-level
mismatches, missing IDs and stale statuses. No owner DB direct read, keys or server access.
Without the runtime export: **INCOMPLETE / HOLD**.
