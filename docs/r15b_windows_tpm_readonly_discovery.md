# R15B Windows TPM Read-Only Backend and NV Discovery

## Scope

This phase authorizes real TPM access only for unauthenticated public discovery.
It does not authorize provisioning, activation, NV data reads, authorization
sessions, NV define/write/extend/undefine, TPM clear/reset, or hierarchy changes.

The Windows path uses TPM Base Services (`tbs.dll`) with a TPM 2.0 raw context.
The implementation exposes only `TPM2_GetCapability(TPM_CAP_HANDLES)` and
`TPM2_NV_ReadPublic`. There is no generic public command-submit API.

## Live host observation

Read-only host probe on 2026-09-11 found TPM 2.0 present, ready, enabled,
activated and owned. Manufacturer is Intel, firmware `403.1.0.0`.
`RestartPending=True`; this is a hard stop for any later provisioning gate until
a reboot and a fresh TPM probe confirm `RestartPending=False`.
## Live NV inventory

The backend enumerated all currently defined NV handles and then verified each
public area with `TPM2_NV_ReadPublic`. Eight handles were present:

- `0x01410001` — TPM_NT_COUNTER, 8 bytes, ORDERLY
- `0x01410002` — TPM_NT_COUNTER, 8 bytes
- `0x01410003` — TPM_NT_COUNTER, 8 bytes
- `0x01800100` — TPM_NT_ORDINARY, 8 bytes
- `0x01810008` — TPM_NT_COUNTER, 8 bytes
- `0x01820002` — TPM_NT_ORDINARY, 8 bytes
- `0x01880001` — TPM_NT_BITS, 8 bytes, non-empty authPolicy
- `0x01880011` — TPM_NT_ORDINARY, 32 bytes

Every current NV public area uses SHA-256 Name and its TPM Name was verified
against the exact marshaled `TPMS_NV_PUBLIC`. No defined `TPM_NT_EXTEND` index
was found.
## Collision discovery

The provisional pool `0x01500020` through `0x0150002f` is entirely undefined
at the observation point. This proves only current collision absence; it does
not allocate, reserve, approve, or bind any one handle. A later provisioning
review must re-run discovery immediately before any irreversible definition.

In particular, `0x01500020` is collision-free now but is not selected by this
phase. Existing Acceptance Origin test fixtures that use a similar numeric
handle do not authorize governance reuse or shared custody.

## What is intentionally still missing

Public discovery cannot supply the R15A `genesis_digest`: no NV content read was
attempted and no authorization session was created. The runtime production
provider therefore remains unprovisioned. A future phase must separately review
how a newly provisioned governance-specific NV_EXTEND index is authorized and
how its exact initial digest is observed without broadening runtime authority.
## Security invariants

- TPM command allowlist contains only GetCapability and NV_ReadPublic.
- Exact command parameter lengths are checked before TBS access.
- TBS uses locality 0 and low application priority.
- TPM response size, tag and response code are validated.
- NV handle enumeration is bounded, ordered and restricted to NV handle range.
- NV_ReadPublic verifies exact returned handle and consumes the full response.
- SHA-256 TPM Names are recomputed from exact inner TPMS_NV_PUBLIC bytes.
- authPolicy is recorded as the policy digest itself, matching the binding contract.
- no NV contents, credentials, auth values, sessions or secret data are requested.
- no MCP tool or broker execution authority is added.

## Stop conditions before any provisioning

1. Reboot the host and require `RestartPending=False` on a fresh probe.
2. Re-run the complete NV inventory immediately before candidate selection.
3. Review an exact governance-specific NV handle and TPMA_NV/authPolicy profile.
4. Keep Acceptance Origin and governance TPM custody/domain bindings separate.
5. Obtain a separate explicit gate for any TPM write or irreversible definition.
