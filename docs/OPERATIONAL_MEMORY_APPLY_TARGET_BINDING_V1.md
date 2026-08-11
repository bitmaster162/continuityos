# Operational Memory Apply Target Binding v1 (R51)

R51 closes cross-clone authorization replay for existing shadow OperationalMemory.

## Reproduced pre-R51 behavior

An R36 DB-backed proposal already contained `operational_memory.path`, and the R37 authorization already bound the exact proposal-file SHA. R37/R44/R45 did not compare the actual DB argument with that bound proposal target. Two byte-identical DB clones therefore had the same projection/cursor/chain identity and could both accept the same proposal plus the same authorization bytes.

## Invariant

A DB-backed R36 proposal is effect-target bound only when:

- `proposal.operational_memory.verified == true`;
- its projection SHA, event cursor and chain head exactly equal the proposal base;
- its bound DB path is an existing regular canonical path with no symlink/junction/reparse/alias ancestor;
- the actual DB path passed to R37/R44/R45 is that same canonical path.

Missing binding is `OPERATIONAL_MEMORY_TARGET_UNBOUND`. Invalid metadata/path is `OPERATIONAL_MEMORY_TARGET_BINDING_INVALID`. A different valid DB is `OPERATIONAL_MEMORY_TARGET_MISMATCH`.

R37 rejects before writable open. R44 never reports READY for a mismatched target. R45 never emits a review packet for a different DB.

## R43 compatibility

R43 claim-sync already reads and verifies one DB. R51 copies that exact metadata into its nested R36 proposal before the proposal is materialized. The existing R37 authorization schema does not change: authorization of the exact proposal-file SHA now also binds the DB target embedded in those bytes.

## Effect ceiling

R51 adds no authority, no automatic authorization and no new apply path. Current R64 sessions remain read-only. Accepted truth, canonical state, deployment, agent dispatch, trading, wallet access and capital permissions remain unchanged/denied.
