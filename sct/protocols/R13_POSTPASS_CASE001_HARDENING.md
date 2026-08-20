# SCT R13 post-PASS Case #001 hardening

Status: `R13_PASS_CASE001_BLOCKED_PENDING_HARDENING`

Scientific authority is frozen and MUST NOT be rerun:

- source SHA `2b3f0288ee35eb8d6554218694f9111e29147dd2`
- source tree `174c5045af3e43b1be62dfc07335de0ea6ea095e`
- R13 scientific calls: exactly 50 existing calls
- preflight `2/2 PASS`
- balanced sentinel `18/18 PASS`
- stable VOID `30/30 PASS`
- qualification SHA-256 `fe64f44570486e9971d451776085c64ac742a0b490f9c43a4d4af73084d02af2`
- `valid_live_n=0`
- `execution_authority=NONE`

## Hardening gate A — receipt-wrapper regression

The component CLI emits the scientific core receipt plus a late `attempt_lifecycle` wrapper field. The core receipt was hashed and recorded before that wrapper was added. `qualify` must canonicalize component input back to the exact recorded core receipt before evidence binding and attestation validation.

Requirements:

1. remove only the non-scientific `attempt_lifecycle` wrapper before qualification binding;
2. require the stripped core receipt SHA-256 to equal the lifecycle/recorded EvidenceStore receipt SHA-256;
3. reject any other wrapper mutation or scientific-field mutation;
4. add regression tests using wrapped component JSON exactly as emitted by the CLI;
5. no model call is permitted by this fix.

## Hardening gate B — LIVE Arm B provenance

The current `open-case` interface accepts caller-provided profile/history text. Before Case #001, the `profile_rag` contestant input must be physically bound to the frozen deterministic Arm B builder `sct.r13-arm-b-profile-rag-builder/v1`.

Requirements:

1. Arm B must be built from the same admitted raw evidence pool available to Arm C at the frozen source cutoff;
2. assistant-authored and SCT-only-derived evidence remain forbidden;
3. the builder must emit a per-case provenance receipt binding scenario/options query hash, source cutoff, admitted-pool hash, policy hashes, payload bytes, and final profile_rag payload SHA-256;
4. `CASE_FROZEN` under active R13 must require that provenance receipt before accepting the case;
5. the receipt must match the actual `profile_rag` frozen contestant input snapshot/payload;
6. direct CLI, direct Python arena, and direct EvidenceStore append bypass attempts must fail closed;
7. frozen baseline manifest and the case provenance receipt must be mutually consistent;
8. CI must cover source-cutoff, pool-hash, payload-hash, policy-hash, and bypass tampering.

## Governance

This branch may implement and test the two hardening gates only.

Forbidden without separate owner authority:

- no new R13 model/scientific call;
- no R13 rerun;
- no Case #001 authorization token;
- no Case #001 open/predict/reveal;
- no merge;
- no deploy;
- no spending;
- `valid_live_n=0`;
- `can_execute=false`;
- `execution_authority=NONE`.
