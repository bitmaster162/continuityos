# R21 Persistent Governance Store Invariant

R21 promotes the R19 production replay-path hardening into a shared ContinuityOS
invariant for long-lived mutable governance authority stores.

A qualifying store path must be file-backed and absolute after `expanduser`.
The shared validator rejects empty values, `:memory:`, SQLite `file:` URIs,
relative paths, and control characters.

The invariant deliberately separates lexical validation from alias resolution.
R18/R19 replay state may resolve filesystem aliases after validation. R14 witness
state must preserve the lexical absolute path so its existing symlink/reparse and
file-identity checks remain authoritative.

## Covered boundaries

- R18 `SQLiteApprovalReplayGuard`
- R19 production Human approval replay binding
- execution `gate.Ledger`
- `GateBroker` registry and ledger stores
- R14 `WitnessAuthority` witness, ledger and registry paths
- current/read-only execution-ledger adapters and direct-surface guard

## Explicit exclusions

R21 does not redefine every persistent path in ContinuityOS. Product memory,
metering, ordinary `Store`, backup/rollback destinations, immutable work-ledger
artifacts, and operational-memory ephemeral modes retain their existing contracts.
They are not treated as mutable governance authority stores by this slice.

R21 also does not claim tamper evidence, rollback detection, distributed CAS,
shared multi-node replay protection, or recovery from external file deletion.
Those properties require separate controls.

## Compatibility boundary

Core CLI and `GateBroker` already derive their default governance files under the
absolute `~/.continuityos` root. Direct low-level `gate.Ledger()` construction no
longer gets an implicit CWD-relative database: callers must provide an explicit
absolute path. This is intentional fail-closed behavior.

No merge, deploy, runtime execution, trading, wallet, or capital authority is
introduced by this invariant.
