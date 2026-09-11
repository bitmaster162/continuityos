# R15 TPM2 Monotonic Execution Anchor

## Scope

R15A is a hardware-free implementation and proof protocol layered on R14.
It does not provision, reset, undefine, read, or extend a real TPM NV index.
The production product path remains R14 until a separately reviewed R15B
activation binds one concrete TPM2 NV_EXTEND provider.

R15 targets the remaining R14 rollback gap: an attacker who restores the
witness, ledger, registry, and lock together can otherwise present a coherent
older local state. R15 requires an external monotonic digest that cannot be
restored with those local files.

## Trust boundary

The provider contract is intentionally narrow. Runtime construction also requires a
controller-pinned `BoundMonotonicAnchorProfile` containing the exact NV public hash,
NV Name hash, and the reviewed pre-activation digest. Activation must start at that
exact digest; it never trusts whatever digest happens to be present at runtime.
The profile itself must be supplied from a controller trust source outside the R14
local rollback domain; a profile restored with the governed SQLite files is not a
valid R15B trust root.

- `read_snapshot()` returns TPM2 NV type plus stable NV public/name identities
  and the observed 32-byte digest.
- `extend(expected_previous_digest, commitment_sha256)` must compare the fresh
  digest, perform exactly one NV_EXTEND, and return a fresh post-extend snapshot.
- no provider reset, clear, undefine, provision, migrate, or arbitrary write API
  is part of the runtime contract.
- R15B must derive those identity hashes from freshly verified raw TPM public/Name
  evidence and bind the reviewed NV index, SHA-256 Name algorithm, TPM_NT_EXTEND
  type, 32-byte data size, non-ORDERLY attributes, authorization policy, and TCTI.
  Merely trusting provider-supplied identity strings is not sufficient for R15B.

## Commitment

Each irreversible anchor advance commits to:

- governance domain `continuityos.governance.execution-anchor.v1`;
- immutable R14 `state_id`;
- strictly increasing local anchor generation;
- phase (`GENESIS`, `EXECUTION_STARTED`, or `EXECUTION_TERMINAL`);
- exact preflight hash and execution binding for execution phases;
- terminal kind for terminal phase;
- exact ledger event count and frontier hash immediately before the receipt;
- previous hardware digest;
- TPM NV public-area and Name identities.

The hardware transition is the TPM2 NV_EXTEND model:

`new_digest = SHA256(previous_digest || commitment_sha256)`

A local `monotonic_anchor` ledger event records the exact commitment and
observed post-extend digest. R14 then witnesses that ledger receipt normally.
The hardware digest is read again after the local receipt before execution may
continue, closing the provider-write/local-receipt TOCTOU window.

## Execution ordering

For an executable broker request:

1. validate R14 witness, registry, ledger, and current monotonic frontier; the
   internal executor repeats the monotonic consistency check before any claim;
2. durably claim the single execution attempt;
3. materialize any required rollback snapshot;
4. durably append and R14-witness `execution_started`;
5. compare-and-extend the monotonic provider for that exact started frontier;
6. durably append and R14-witness the monotonic START receipt;
7. freshly re-read the hardware frontier and require exact equality;
8. only then enter the existing sole `cli._execute_approved` subprocess call;
9. durably append and R14-witness the terminal execution event;
10. compare-and-extend and persist the exact TERMINAL anchor receipt.

A cached terminal result is valid only when an attempted execution has both its
START and TERMINAL monotonic receipts and the fresh provider state equals the
latest local receipt. Every post-activation `execution_started` event must be
covered by its adjacent START receipt, and every effect-bearing terminal event
must be covered by its adjacent TERMINAL receipt. A terminal failure before any
subprocess boundary does not require hardware advancement.

## Crash and rollback semantics

There is deliberately no runtime auto-heal of a hardware/local mismatch.
If hardware advances but its local receipt is not durable, restart is HOLD.
If hardware is unavailable or an extend fails before START completion, no
subprocess is run and the runtime remains fail-closed. Any post-activation
STARTED boundary lacking its monotonic receipt globally blocks further governed
work. If a START receipt exists but no verified terminal outcome or TERMINAL
receipt exists after a possible effect, the entire runtime is HOLD until explicit
offline reconciliation. R15A deliberately provides no runtime auto-recovery for
these states.

Restoring all R14 local files to an older coherent checkpoint leaves the TPM
digest ahead of the last local monotonic receipt and therefore fails closed when
the runtime is constructed with the controller-pinned R15 provider/profile. Once
a local GENESIS anchor receipt is visible, legacy R14-only broker startup and
preflight are rejected, and direct execution is blocked before claim, as defense
in depth. That local downgrade marker is not the R15 trust root: a coherent rollback can erase it, so production R15B must make
provider/profile enablement mandatory from controller state outside the R14 local
rollback domain. Changing the NV public or Name identity also fails closed.

## Activation and remaining limits

`bind_genesis()` is an offline-only R15A primitive. It performs one monotonic
advance and binds the current verified R14 state; the broker never invokes it
automatically. The provider identity and pre-activation digest must already match
the controller-pinned profile. If hardware advances but the activation receipt is
lost, a second activation refuses to extend again. Trust begins at that explicit
activation point. Production R15B must add independently reviewed provisioning,
exclusive-write custody, and profile distribution, and must not expose activation
or TPM administration through MCP.

R15 does not protect against an actor able to reset/reprovision the trusted TPM
and simultaneously replace the configured hardware identity/trust policy, nor
does it claim OS-level universal interception. Those remain higher-layer trust
and deployment concerns.
