# Current Project Update Packet Preflight v1 (R54)

`continuity-project-update-preflight --db PROJECT.db --packet REVIEW_PACKET.json --authorization AUTHORIZATION.json` removes the remaining need to materialize the embedded R52 proposal file merely to perform the read-only preflight after a separate authority decision.

## Inputs

- the exact R52 `CURRENT_PROJECT_UPDATE_REVIEW_PASS` packet;
- a separately completed R37 authorization artifact produced by a HUMAN or DETERMINISTIC_CONTROLLER action;
- the exact existing shadow OperationalMemory DB.

R54 does **not** fill authority fields and does not authenticate the claimed authority identity. The authorization must already contain `decision`, `authority_class`, `authority_id`, `authority_ref`, `apply_recorded_at`, and `rationale`.

## Validation

Before returning READY, R54 verifies:

1. R52 packet identity (`packet_id`) and its NOT_APPLIED / HOLD ceilings;
2. exact embedded `proposal_canonical_json`, byte size, SHA-256 and R37 proposal identity;
3. the completed authorization with the real R37 authorization validator;
4. the R51 canonical DB target binding;
5. immutable OperationalMemory verification and exact R36/R37 base identity;
6. replay state;
7. operation targets through the R44 checker.

The proposal never has to be written to disk for this review step. The authorization SHA is derived from the exact raw authorization-file bytes read by the verified-current CLI.

## Effect boundary

`CURRENT_PROJECT_UPDATE_PREFLIGHT_READY` means only that the packet, authorization record, memory base and operation targets are valid at that point in time. It does not authenticate the authority identity, grant execution or apply memory.

For an actual update, the exact `proposal_canonical_json` must still be materialized byte-for-byte and R37 must be invoked from a separate unbound process with the exact authorization artifact. R37 revalidates all requirements under its own write lock before an atomic commit.

Current R64 sessions remain READ_ONLY. No R64/Drive/canonical mutation, deployment, agent dispatch, trading, wallet access or capital permission is introduced by R54.
