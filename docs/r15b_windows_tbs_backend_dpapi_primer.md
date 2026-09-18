# R15B Windows TBS Runtime Backend, DPAPI Custody, and Primer

## Scope

This patch prepares a real Windows TPM 2.0 runtime backend without performing
any TPM mutation. It separates three responsibilities:

- windows_tpm_runtime.py: normal runtime read/extend only;
- windows_tpm_dpapi.py: DPAPI custody for the 32-byte NV index authValue;
- windows_tpm_provisioning.py: offline-only define plus one primer extend.

The provisioner is not imported by MCP, broker, CLI, or runtime entrypoints.

## Reviewed host/profile

EK public-key SHA-256:
d4493341ea776e196234af9547d2a22118767eea3a0312d00e445fa497f6469c

Reviewed candidate handle: 0x01500020.
Owner-created definition mask: 0x02040044.

Flags are AUTHWRITE, TPM_NT_EXTEND, AUTHREAD, and NO_DA.
OWNERREAD, OWNERWRITE, PLATFORMCREATE, and ORDERLY are absent.

Windows TBS storage ownerAuth is used only by the offline define operation.
Runtime never retrieves ownerAuth and authenticates only with index authValue.

## Why a primer is mandatory

TPMA_NV_WRITTEN is clear immediately after NV_DefineSpace and becomes set after
the first successful write/extend. TPMS_NV_PUBLIC includes that attributes
field, so the transition changes both the public hash and TPM Name.

R15B pins exact public bytes and Name. Normal governance therefore activates
only after one domain-separated provisioning primer. Stable active mask:
0x22040044.

Reviewed hashes:

- definition public: 27b26b0e2f7a5f11d63615367817fbbd52410c778e78bfd0c66adc88f9d6d103
- active public: 4e6f663d09b9af433074e55b967ba1f201c5e34c8db8eee7a7ae372855642063
- active Name: 5f350a71c3e0946639146d182d5f345d1e7203824a77fcd29cbf654fcc110fc5
- primer: db5a5fa1867e616716b0c3d34e94a87a58c53875f9d5e11b9782756545074ec0
- primed genesis: 54d69bcdee19684366afcc77cf894482b81fc0864e9b43d769adc020632147e4
- active binding: d732c991382a2edb99b9dcb39063224c2a62df2c56813668e76a74444c2965d4

## Secret custody

The index authValue is exactly 32 random bytes. The offline provisioner
generates it using the Windows system CSPRNG and stores it through current-user
DPAPI before attempting NV_DefineSpace.

The persisted envelope contains ciphertext plus public binding metadata only.
DPAPI optional entropy binds ciphertext to the exact NV handle and EK hash.
Runtime loads plaintext into mutable bytearray memory and zeroizes it after each
authorization operation.

Storage ownerAuth is obtained from TBS in memory only, is never persisted or
returned in evidence, and is zeroized after NV_DefineSpace.

## Runtime command boundary

The normal runtime private TBS transport accepts only TPM2_NV_Read and
TPM2_NV_Extend. Public identity remains verified through the existing
TPM2_NV_ReadPublic boundary.

Runtime has no define, undefine, clear, reset, ownerAuth retrieval, hierarchy
management, provisioning, or generic command-submit API.

## Offline ceremony

A later separately authorized hardware ceremony must:

1. require PPI=0, RestartPending=False, TPM ready, and lockout count 0;
2. re-enumerate NV handles and require 0x01500020 absent;
3. require the reviewed EK public-key hash;
4. persist a fresh DPAPI-protected index authValue;
5. retrieve storage ownerAuth in memory only;
6. execute exactly one TPM2_NV_DefineSpace;
7. re-read and verify the unprimed public identity;
8. execute exactly one primer TPM2_NV_Extend;
9. re-read the stable WRITTEN=1 public identity;
10. authorized-read the digest and require reviewed primed genesis;
11. emit only public evidence and stop.

The effectful method additionally requires its generated exact hardware-write
authorization token. This patch does not call that method.

## Failure model

If DPAPI custody creation fails, no TPM mutation is attempted. If a mutation
occurs and later verification fails, execution stops. It does not auto-undefine,
clear, recreate, or re-enroll the index.

External TPM clear or deletion makes the bound profile unavailable and must fail
closed. Recovery requires a new explicit enrollment/provisioning authority.

## Current status

This branch is preparation only. No real NV_DefineSpace, NV_Read, NV_Extend,
NV_UndefineSpace, TPM clear/reset, reboot, bind_genesis, deploy, signing,
trading, or capital action is authorized by this patch gate.

Reviewed plan fingerprint:
5ecae1fc79cf17f30862aa6f4678439e76d4e1c12a85ad47f3d7347f8b83aad1

Generated future hardware-write token:
APPROVE_CONTINUITYOS_R15B_HARDWARE_PROVISION_5ECAE1FC79CF17F3


## Crash-resumable forward-only state machine

Provisioning recovery is derived from durable DPAPI custody plus current TPM
public state. It does not trust a local progress marker.

The only resumable states are:

- EMPTY: no custody and reviewed handle absent;
- CUSTODY_ONLY: custody exists and handle absent;
- DEFINED_UNPRIMED: custody exists and exact definition public area is present;
- PRIMED_UNVERIFIED: exact active WRITTEN public area is present but authorized
  digest verification did not complete;
- PRIMED_VERIFIED: exact active public area and reviewed primed genesis digest
  are both verified.

Forward transitions are bounded to:
EMPTY -> CUSTODY_ONLY -> DEFINED_UNPRIMED -> PRIMED_UNVERIFIED/PRIMED_VERIFIED.

A lost response after NV_DefineSpace is recovered by observing the exact
definition public area and continuing with primer; NV_DefineSpace is not
repeated. A lost response after primer is recovered by observing the exact
WRITTEN public area and performing verification only; primer is not repeated.

A handle without custody, an unreviewed public area, or an active digest that
differs from the reviewed primed genesis is a hard HOLD. Recovery never invokes
NV_UndefineSpace, TPM Clear, deletion, rollback, or automatic re-enrollment.


## Password authorization response parsing

TPM password authorization responses are expected to contain an empty nonce,
sessionAttributes equal to 0x01 (continueSession), and an empty HMAC. The TPM
2.0 specification requires continueSession to be SET in a response associated
with password authorization even though it has no password-session lifetime
semantics.

The parser therefore accepts exactly 0x01 for the response attributes and
rejects 0x00 or any additional session-attribute bits. This matches the
observed hardware response auth area 0000010000.
