# R15B TPM2 Real Provider Binding

## Status and authority

R15A is closed on protected master `ea0106f630997e00d3ad5853ffc6923e0e392502`.
R15B begins from that exact merge and prepares the real TPM2 provider binding.

Current authorization is design and local non-destructive preparation only.
This phase may create local source, tests, docs, evidence, and read-only host probes.
It does not authorize a TPM/NV mutation, provisioning ceremony, activation, push,
PR, merge, deploy, production signing, trading, or capital action.

No runtime or MCP administration surface is introduced by this phase.

## Security objective

R15A proved the monotonic execution protocol with an injected provider. R15B must
bind that protocol to one dedicated governance TPM2 NV_EXTEND identity whose
state cannot be rolled back with the R14 local files.

The trusted profile must live in controller state outside the R14 rollback domain.
A profile restored together with ledger/witness/registry is not an R15 trust root.

## Governance NV binding

The R15B binding is intentionally stricter than the R15A three-hash profile.
It pins all of the following before activation:

- one TPM NV handle in the TPM NV handle range;
- exact `TPMA_NV` attributes;
- `TPM_NT_EXTEND` type;
- SHA-256 Name algorithm;
- 32-byte data size;
- `ORDERLY` must be false;
- exact authorization-policy bytes, or reviewed explicit absence;
- backend kind and transport identity;
- SHA-256 of exact inner `TPMS_NV_PUBLIC` wire bytes;
- SHA-256 of the exact raw TPM Name;
- reviewed pre-activation NV digest.

The dedicated governance index must not be reused from Acceptance Origin or any
other application. Cross-domain custody reuse would collapse the trust boundary.

## Enrollment evidence and controller pin

Enrollment starts from a read-only raw snapshot. The snapshot must include the
exact inner `TPMS_NV_PUBLIC` bytes, exact raw TPM Name, observed 32-byte digest,
and the reviewed non-identity constraints.

R15B recomputes the TPM Name as `nameAlg || H(TPMS_NV_PUBLIC)` and rejects any
provider-supplied identity string that disagrees with those raw bytes.

`derive_profile_candidate()` creates a review candidate only. It is not a
self-authorizing enrollment operation. The candidate exposes a deterministic
binding document and SHA-256 fingerprint. That fingerprint must be approved and
pinned by controller state outside the local rollback domain before activation.

Runtime must never derive a fresh trusted profile from whatever TPM state happens
to be visible at startup. Identity drift is HOLD, not automatic re-enrollment.

## Provider/backend split

`BoundTpm2NvExtendProvider` is the governance-facing provider. It performs no
hardware I/O itself. It validates every backend snapshot against the full bound
profile and emits only the narrow R15A provider shape.

Its `extend()` path is compare-before-write:

1. fresh read and strict identity/profile validation;
2. require the fresh digest to equal `expected_previous_digest`;
3. call exactly one backend `extend_once()` operation;
4. validate returned identity and expected digest transition;
5. fresh read again and require byte-for-byte provider-state equality.

`UnprovisionedTpm2NvBackend` remains fail-closed. A production backend must be a
separately reviewed component with exclusive write custody; it must not expose
reset, clear, undefine, define, arbitrary write, or migration APIs to runtime.

## Read-only Windows host finding

The current authorized read-only probe reports a real TPM 2.0 device: present,
ready, enabled, activated, owned, and initialized. Manufacturer is Intel,
firmware `403.1.0.0`; Windows reports no vulnerable TPM firmware condition.

Native `tpm2-tools` executables are not installed. WSL currently exposes only
`docker-desktop`, so a Linux TCTI path is not an established production boundary.
The likely Windows implementation path is therefore a separately reviewed local
Windows TPM stack/backend rather than shelling out to `tpm2-tools`.

`Get-Tpm` currently reports `RestartPending=True`. This is a hard provisioning
stop condition for this preparation: no NV selection, definition, activation, or
write should occur until the host has rebooted and a fresh read-only probe shows
a stable TPM state with no pending restart.

## Future provisioning ceremony — not authorized by this phase

A later explicit gate must bind one unused governance-specific NV index only after
read-only collision discovery. The exact handle, complete attributes, auth policy,
write/read authorization mechanism, transport/backend identity, and expected
initial digest must be reviewed before any TPM mutation.

No default NV handle or authorization mode is permitted. The ceremony must fail
closed if the chosen handle already exists, if the TPM public area differs from
the approved profile, or if the initial digest is not the reviewed genesis value.

After definition, the ceremony must re-read exact public bytes and TPM Name,
produce controller-pinned binding evidence, and only then consider R15 activation.
Activation remains a separate irreversible step because `bind_genesis()` advances
the monotonic digest once.

Provisioning and activation must never be exposed through MCP or normal broker
runtime. Administrative recovery is an offline owner operation with separate
authority and evidence.

## Current preparation acceptance criteria

This R15B preparation is acceptable only if:

- the new binding/provider module has no hardware/effectful imports;
- no Acceptance Origin custody module is imported or reused;
- no TPM admin API is added to the product surface;
- unprovisioned backend remains fail-closed;
- strict raw public/Name/profile drift tests pass;
- stale-frontier attempts are rejected before backend mutation;
- post-extend movement is detected;
- R15A, Acceptance Origin custody, GateBroker, MCP, and direct-surface regressions remain green;
- repository scope contains source/doc/tests only; runtime logs stay out of product scope;
- no remote branch, PR, merge, deploy, signing, or TPM mutation occurs.

A local commit is not implied by this authorization and should require a separate
explicit gate if the prepared candidate is to be frozen for promotion.

## Next gates

The next safe step after this preparation is a separately authorized read-only
Windows backend/discovery phase, for example:

`APPROVE_CONTINUITYOS_R15B_WINDOWS_TPM_READONLY_BACKEND_AND_NV_DISCOVERY_ONLY`

That phase may prove exact raw NV public/Name reads and enumerate candidate-handle
collisions, but still must not define, extend, reset, clear, or undefine anything.

Only after read-only discovery, reboot/re-probe, and exact profile review should a
provisioning token name the approved binding fingerprint and exact NV handle.
Provisioning, first monotonic activation, and normal live runtime enablement should
remain separately gated irreversible transitions.
