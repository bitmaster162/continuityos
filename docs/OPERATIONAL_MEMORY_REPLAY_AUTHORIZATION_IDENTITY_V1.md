# Operational Memory Replay Authorization Identity v1 (R48)

R48 closes an audit-lineage ambiguity in R37/R44 replay handling.

Before R48, R37 considered an already-applied delta replay exact when `proposal_id` and proposal bytes matched the durable apply event. The newly presented authorization was still structurally validated, but its bytes were not compared with the authorization bytes recorded in the historical `MEMORY_DELTA_APPLIED` event.

A reproduced case on the R47 CI-built wheel showed the problem:

1. proposal P was applied under authorization A;
2. the same proposal P was replayed with a different valid authorization B;
3. R37 returned `CURRENT_MEMORY_APPLY_ALREADY_APPLIED`;
4. the top-level receipt reported authorization SHA B while the durable event payload reported authorization SHA A.

R44 exposed the same ambiguity in its read-only `ALREADY_APPLIED` preflight.

R48 preserves historical R37/R44 bytes and installs a post-import replay guard. Exact idempotent replay now requires both:

- exact proposal identity/bytes, as before;
- exact authorization file SHA matching the durable apply event.

Exact A replay remains `ALREADY_APPLIED` and performs no write. A B replay becomes fail-closed `REPLAY_AUTHORIZATION_IDENTITY_MISMATCH`; the receipt explicitly separates `presented_authorization_file_sha256` from `durable_authorization_file_sha256` and retains the durable event as evidence. R44 marks the historical effect `ALREADY_APPLIED` but does not require or authorize an effectful retry.

The R48 R37 hook composes with the existing R46/R47 temporal apply loader rather than competing for the same import. R44 has its own lazy hook because no prior guard owns that module.

No new authority, identity authentication, memory effect, accepted truth, canonical-state mutation, deployment, dispatch, trading, wallet access, or capital permission is introduced.
