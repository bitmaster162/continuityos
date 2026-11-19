# ContinuityOS H3-R7A1 — Security Architecture & Verification Matrix v1.0-DRAFT

**Date:** 2026-10-11 (Asia/Bangkok)  
**Status:** R7A1 LOCAL WRITE PASS / R7A2 AND R7A3 LOCAL REPAIRS PASS / R7A4 OWNER-APPROVED IN-PLACE DOCUMENT REPAIR / DESIGN DRAFT ONLY / UNTRACKED / NO COMMIT / NO RUNTIME AUTHORIZATION  
**Approval:** Owner approvals H3-R7A1 LOCAL_DOC_WRITE_ONLY_R1, H3-R7A2 DOC_REPAIR_LOCAL_ONLY_R1, H3-R7A3 DOC_REPAIR_LOCAL_ONLY_R1 and H3-R7A4 DOC_REPAIR_LOCAL_ONLY_R1 authorize only creation and in-place edits to this single local Markdown file. No git add/commit/push/PR/merge/deploy, service registration, ACL/TPM/IPC/DB/MCP/Scheduler mutation, or production activation is authorized.  
**Repository:** `bitmaster162/continuityos`, protected branch `master`  
**Source anchor:** `c2b2a3ed1ddd7a2d8b39ff16e3e6d9b8ce419f90`  
**Tree anchor:** `1c8cc40c36841eaef41b572325298e67473e6c4c`  
**Merge origin:** PR #207, normal merge of `f3e5b71105b8e9e43c6bcc99a1e7202cfdeb1253`  
**Independent offline baseline:** `C:\Users\coins\AppData\Local\ContinuityOS\h3-r6i-baseline-candidate-20261011` (detached at the source anchor; initially CLEAN, now only this untracked design file).  
**Local repository path (written, untracked; not committed):** `docs/H3_R7A1_SECURITY_ARCHITECTURE_20261011.md` in the independent clone.

## 0. Evidence labels and design authority

- **IMPLEMENTED:** observed in the source at the exact anchor above.
- **EXTERNAL VERIFIED:** verified against public Microsoft Windows documentation; applicability to this machine and exact configuration still needs lab testing.
- **DESIGN PROPOSAL:** an intended new component/constraint; not implemented or proven.
- **UNVERIFIED/HOLD:** evidence is missing; treat as a failed authorization gate.
- **NO PRODUCTION CLAIM:** neither green Python tests nor a synthetically successful `MODEL_ALLOW` can grant Windows access to live memory.

**Implemented source facts:**

1. `continuityos/h3/readonly_contract.py` implements pure offline JSON request/response validation for `continuityos.h3.ipc/v3` with `MAX_REQUEST_BYTES = 16*1024`, `MAX_RESPONSE_BYTES = 8*1024`, `MAX_RESULTS = 10`, and exactly the methods `memory_status`, `list_namespaces`, `find`, `recall`, `context`.
2. Responses bind to the full validated canonical request using a domain-separated **public SHA-256** digest. This is a consistency check, **not a signature, MAC, confidential channel, principal proof, or anti-replay mechanism**.
3. `continuityos/h3/authz_decision.py` implements synthetic dataclasses and fail-closed checks. They do **not** obtain real OS identity, attest a broker, verify signatures, read a witness, or commit replay state. The final synthetic success result is `MODEL_ALLOW`, never a runtime capability.
4. H3 source rejects specified control/bidi code points, preserves normal multilingual characters/ZWJ/ZWNJ, and keeps limited TAB/LF only for returned text.
5. Existing `continuityos/mcp_server.py` and `remote_mcp_server.py` are **not H3 native brokers**; the repo README explicitly does not claim universal interception of shell, MCP, SDK or agent tool calls.
6. The independent baseline has been checked for exact HEAD/TREE and 107/107 H3 offline unit tests. Those unit tests do not validate a live Windows RPC/DB isolation boundary.

## 1. Objective and explicit non-goals

**Security objective:** an untrusted AI agent may request bounded, explicitly owner-authorized, read-only memory disclosure. The response must be derived from independently verified *current call identity*, independently verified grant scope, fresh witness/replay state and a reader whose private storage is unreachable by the agent. No action occurs without a positive chain of trust. Every failed or unknown boundary results in `DENY` or `HOLD` without metadata or content leakage.

**Non-goals of R7A1:** installation or registration of a Windows service; modification of filesystem/registry ACLs; real `ncalrpc` listening endpoint; access to existing SQLite/WAL; modifying Windows Defender, TPM, DPAPI keys or scheduler; changing any Git ref; deployment; accepting an AI-supplied boolean as an OS fact.

**Threat actors:** malicious/compromised AI agent; untrusted AppContainer payload; separate standard desktop process under same user; other local Windows user/session; forged local RPC endpoint; copied/corrupted grant; race on revocation; replay after restart/crash; local storage bypass and symlink/reparse race; resource exhaustion through oversized requests or response expansion. A local administrator/SYSTEM attacker is *not* claimed to be isolated by conventional Windows DACLs; stronger claims require separately reviewed hardware/root-of-trust assumptions.

**Trust boundaries:**

`Agent (untrusted) -> trusted client-side SERVER_TRUST_VERIFIED BEFORE any v3 application payload -> local RPC interface ACL -> current-call Windows token evidence -> owner-grant verifier -> independent witness + atomic replay ledger -> protected read-only memory process -> pre-disclosure revocation/response checks -> durable disclosure_intent BEFORE first protected reply byte -> bounded reply -> terminal audit receipt`.

The broker alone owns verified evidence. The client controls only the bounded request. Never deserialize a client-supplied `AdmissionEvidence` as verified authority.

## 2. Proposed components and ownership

| Component | Trust level | Input | Trust source / output | Must not do |
|---|---|---|---|---|
| AI / AppContainer client | Untrusted | Prompt, tool params | Serialized v3 request only | Set verified evidence bits, read DB/WAL, choose service identity |
| Native H3 RPC process | Trusted only after verified deployment | Windows RPC call | Per-call transport and caller-token evidence | Accept client evidence or fallback to untrusted token values |
| Client-side server verifier | Trusted ONLY when independently OS-protected from AI/AppContainer-writable code, configuration and pins; otherwise UNVERIFIED/HOLD | Protected verifier obtains authenticated proof for the current RPC binding | Independently owner-pinned server identity/key inaccessible to the agent | Let the agent replace/disable the verifier, inject accepted proofs, or claim arbitrary RPC callers satisfied C0 |
| Owner-grant verifier | Separate pinned authority | Signed, versioned grant and current session | Verified owner signature, scope, expiry, revocation epoch | Accept `signature_verified=True` as proof |
| Witness / monotonic revocation | Independently governed | Epoch/read-only query | Authenticated fresh epoch and revocation state | Derive current truth from same writable files as broker |
| Replay store | Protected, atomic | Canonical replay key `(installation_id, session_id, request_id, nonce)`, independent of grant version or epoch | Durable single-winner reservation, with grant/key/epoch bound as verified immutable metadata | Allow a changed grant or epoch to reset the same request/nonce reservation after restart |
| Memory reader | Separate service identity, read-only at OS boundary | Verified, authorized read plan | Narrow rows/content under checked DB and WAL DACLs | Writable SQL, schema changes, unbounded dumps |
| Response and audit | Trusted disclosure gate | Candidate records, decision evidence | Final scope+epoch check, privacy-preserving audit receipt | Include sensitive content in DENY, errors, logs |

**Design choice to validate:** use a dedicated service process with its own service SID and only necessary OS privileges; evaluate `SERVICE_SID_TYPE_RESTRICTED` in a disposable lab. Do not co-host H3 in a process containing unrelated RPC interfaces. Separate identities/ACLs are required to make broker compromise and direct-storage bypass hard to conflate.

## 3. Windows RPC authorization design (not implemented)

1. Only a dedicated `ncalrpc` server endpoint is within the intended transport profile; reject network transports, unsolicited named-pipe fallbacks, implicit endpoint substitution, alternate interface bindings and unauthenticated local requests. Endpoint names are discovery data, not security identities.
2. Register an **interface-level** DACL with `RpcServerRegisterIf3`, plus a strict callback. Microsoft documents that the default RPC interface descriptor for a non-AppContainer server does **not** allow AppContainer calls, so an explicit *narrow* allowance must be proven in the lab.
3. Enforce `RPC_IF_SEC_NO_CACHE` where callback decisions must reflect the current call; verify callback count with repeated calls and identity/revocation transitions. A flag's presence is not equivalent to tested behavior.
4. Treat `RPC_IF_ALLOW_SECURE_ONLY` as a necessary defensive setting only where appropriate, never sufficient authorization: authenticated callers may have low privilege.
5. **Important ncalrpc exception:** the `MaxRpcSize` parameter on `RpcServerRegisterIf3` **does not enforce an incoming size bound on ncalrpc**. Enforce a byte budget **before allocation/JSON decoding** in the native stub/reader, plus the H3 v3 16-KiB request and 8-KiB response checks. The explicit marshaling/IDL allocation policy is a separate design gate.
6. For each call, establish RPC authentication context and impersonate **only the active caller**. Treat any non-success `RpcImpersonateClient` as `DENY`; never proceed under the service process token. Validate impersonation level and check `OpenThreadToken` / `GetTokenInformation` data against a pinned policy, including User SID, `TokenIsAppContainer`, `TokenAppContainerSid`, integrity, and actual capability groups. Check identity-level impersonation limitations.
7. `RpcRevertToSelf` or `RpcRevertToSelfEx` must succeed in a guaranteed cleanup path. On revert failure, stop using that thread/process and enter `HOLD`; the callback must not cache the earlier identity or authorization decision.
8. The trusted client MUST verify the *server* before transmitting any H3 v3 application request or confidential query/key/namespace data. Default local RPC binding does not supply mutual server authentication. Require a fresh challenge and cryptographic proof verified against an independently owner-pinned server principal or key, bound to installation, session, server instance, trust epoch and the same channel/binding. The pre-send handshake may transmit only non-sensitive discovery/challenge data, never the protected request. An endpoint name, PID, localhost, code signing alone or public request SHA-256 is not sufficient. Reconnect, restart or epoch drift invalidates prior proof; a failed proof sends zero H3 application payload bytes. The handshake is an unimplemented design dependency, not an added v3 memory method.
**R7B0 RPC mutual-auth profile to verify (DESIGN PROPOSAL, NOT A PASS):** On the trusted client binding, evaluate `RpcBindingSetAuthInfoExW` with `RPC_C_AUTHN_WINNT`, an expected server principal/SPN independently pinned by the owner (never learned from the untrusted endpoint), `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`, and `RPC_SECURITY_QOS.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH`. Explicitly select and inspect impersonation level, identity tracking and the effective security provider. Microsoft documents `ncalrpc` support, but API/QOS success is **not sufficient proof**: NTLM may report mutual negotiation without providing real mutual server authentication. Require independent proof of the expected server identity and same-binding freshness, including same-user fake-server, wrong-SPN, downgrade, restart and reconnect negatives. If this profile cannot prove genuine server identity, HOLD or require an independently owner-pinned signed challenge whose private-key custody is outside the agent; never use anonymous/unauthenticated fallback or send H3 application bytes before proof. See [RpcBindingSetAuthInfoExW](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingsetauthinfoexw), [RPC_SECURITY_QOS](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos) and [Choosing Security QOS](https://learn.microsoft.com/en-us/windows/win32/rpc/choosing-security-qos-options).

9. Exact `TokenCapabilities == ()`, `LOW_IL_SID = S-1-16-4096` and AppContainer SID pattern in the synthetic model remain **unverified assumptions**. R7B0 must measure a real token and decide whether to revise policy. Do not silently weaken checks to get a positive test.
10. No real service registration or DACL changes may occur at R7A1/R7B0 design-only scope without separately approved disposable test setup and rollback evidence.

## 4. Authorization sequence and fail-closed state machine

**Two-sided admission and disclosure sequence (DESIGN PROPOSAL; broker unimplemented):**

**C0 — `CLIENT_PRE_SEND_SERVER_TRUST_VERIFIED` (trusted client-side prerequisite, BEFORE any H3 v3 application request bytes).** The client independently authenticates the broker through a fresh challenge and a pinned trusted service principal/key. Proof must bind the installation, session, server instance, current trust epoch and the specific channel/binding used for the following request. No namespace, query, key, sensitive parameter, memory payload or reusable grant secret may be sent during discovery/challenge. Failure, reconnect, broker restart or epoch drift means no H3 application request is sent. C0 cannot be satisfied by endpoint name, PID, server self-report, caller-supplied flags or the unkeyed request SHA-256. This proposed pre-send handshake is outside the existing v3 memory-method set. **C0 is guaranteed only for the approved, OS-isolated client path**, not for an arbitrary malicious RPC caller. An agent may bypass its wrapper and send data it already knows to a rogue listener; this architecture cannot prevent that outbound behavior. The actual broker must independently enforce current-call OS identity, signed grants, witness, replay and namespace checks; bypassing the trusted client path must never yield protected memory. R7B0/B1 must prove the verifier and its trusted pins are not writable or replaceable by the agent.

**Server-side sequence (possible only AFTER client C0):**

1. `RECEIVED`: reject oversize frames before allocation; parse and validate H3 v3, exact method, canonical params, Unicode and bounded numbers. Unknown method or v1/v2 -> `DENY`.
2. `CLIENT_VERIFIED`: enforce the RPC interface ACL/callback and obtain independently verified **current-call Windows token** evidence through successful impersonation. Compare User SID, Package/AppContainer SID, integrity and capability claims against the pinned OS client policy. **The Windows token does not establish `installation_id`**; do not derive or trust installation identity from RPC parameters or token metadata. Failure -> `DENY` without memory access. Client-side server authentication C0 is independent.
3. `OWNER_GRANT_VERIFIED`: independently verify the canonical signed grant, owner-pinned public key, key epoch, validity interval and permitted method/namespace scope. Obtain `installation_id` from separately owner-pinned trusted broker installation configuration, then require the signed grant's installation ID to match it, and the grant's user/package/session bindings to match independently verified policy and current-call evidence. Do not infer installation identity or permissions from the caller's SID alone; mismatch -> `DENY`.
4. `REPLAY_RESERVED`: atomically and durably reserve the sole canonical replay key `(installation_id, session_id, request_id, nonce)` in protected storage in state `PENDING_WITNESS`. A different grant ID, signature, owner key epoch or witness epoch **must not create a fresh reservation** for the same tuple. Persist the independently verified grant ID, grant/key epoch and scope as associated immutable metadata, never as replay-key components. **Do not attach or claim a verified witness epoch at this step:** it has not yet been obtained from the independent witness. Any duplicate, ambiguous durable reservation or rollback -> `DENY/HOLD` before disclosure; never release or reset the reserved tuple on grant rotation or restart.
5. `WITNESS_VERIFIED`: after the replay reservation is durable, obtain and independently authenticate the monotonic witness receipt; verify signature/provenance, freshness, revocation and epoch agreement with the validated owner grant. **Only after successful verification**, atomically and durably bind the verified witness receipt/epoch to that existing replay reservation, then mark it `WITNESS_VERIFIED` before `READ_PLAN`. Missing/invalid/stale/revoked/mismatched witness, rollback, failed or ambiguous atomic binding -> internal `HOLD`; preserve the already consumed replay tuple and permit **zero `READ_PLAN`, DB reads or protected disclosure**. Never treat an unverified epoch as committed evidence, fall back to local cached allow, reset the nonce or auto-retry after a crash.
6. `READ_PLAN`: compile exclusively parameterized, non-mutating queries; enforce namespace and count limits; verify protected DACL/path/container ancestry without following unsafe reparse points. DB direct access by agent must fail at OS layer.
7. `READ`: obtain candidate result through protected read-only adapter; do not grant permission to execute SQL or choose DB path via RPC.
8. `PREDISCLOSURE_CHECK`: independently recheck current grant/witness/revocation and result classification **immediately before the disclosure intent**; stale/revoked -> `DENY/HOLD`, discard candidate. The eventual implementation must close or bound any check-to-send revocation race, not assume this check is atomic with transport.
9. `DISCLOSURE_INTENT_DURABLE`: **before the first protected response byte**, persist and durably acknowledge an append-only intent linked to the atomic replay reservation. Record request/response digest, server/session/installation identity, approved scope, grant key epoch, witness epoch, classification, intended byte count and intent ID; never record plaintext memory, keys or tokens. A failed/ambiguous durable commit is `HOLD` and releases **zero protected content bytes**. A safe denial envelope is allowed without content.
10. `REPLY`: only after a verified client C0, successful server checks and durable intent, enforce exact H3 response schema, 8-KiB ceiling, namespace binding and statuses `ok|not_found|denied`. Explicitly track send attempt, partial write, disconnect and acknowledgement uncertainty. Do not equate local send completion with confirmed client receipt.
11. `TERMINAL`: attempt to durably persist terminal delivery-attempt evidence linked to the intent. Mark confirmed delivery only with separately verified acknowledgement; otherwise use `DELIVERY_UNKNOWN`/`HOLD`. A write failure after possible transmission must retain the intent and never be relabelled as `NOT_SENT` or silently successful.

**Recovery and unknown delivery:** a crash/power loss before intent must preserve the replay reservation and recover to `HOLD`, not release an automatically retriable request. A crash after durable intent but before first byte, mid-stream, or after send before terminal receipt is `DELIVERY_UNKNOWN/HOLD`; content may already have been disclosed and the same replay tuple must never be re-served automatically. Reconcile only with independent evidence and separately reviewed rules; do not assert exactly-once delivery or reset the replay store, witness, intent journal or revocation history to make a run pass.

## 5. Data protection and disclosure limitations

- Future SQLite adapter must use a distinct Windows security identity, immutable allowlisted DB path and read-only mode, with OS DACL denying all untrusted processes direct access to DB, `-wal`, `-shm`, backups, snapshots and exports. SQLite `mode=ro` or `PRAGMA query_only` is defense in depth, **not a substitute** for Windows DACLs.
- No caller-controlled filesystem path, SQL string, WAL directory, external attachment, extension load or URI parameters. Enforce per-record classification and per-call disclosure scope.
- `DENY` returns empty content and no sensitive metadata; `not_found` is allowed only after verified authorization and should not reveal unauthorized namespace existence.
- Audit may contain synthetic decision identifiers, scope hashes, epoch, disclosure-intent ID, intent/terminal state and status; never full memory content, grant secrets, auth tokens, private keys or raw personal data. Durable `disclosure_intent` must precede any protected reply bytes. Terminal/ack evidence follows the send attempt; missing evidence leaves `DELIVERY_UNKNOWN/HOLD`, not a fabricated `NOT_SENT` or success.
- **Storage-failure policy:** SQLite/WAL recovery failure, database locks, unreadable files, I/O faults or inconsistent snapshots result in broker-internal `HOLD` and **no protected memory disclosure**. They must never map to `not_found`. Only a successfully completed, authorized, no-hit `find` or `context` lookup may produce the wire status `not_found`. If the trusted broker can form a bounded, valid, content-free v3 refusal, it may send `denied` with `result=null`; otherwise suppress the reply and retain `HOLD`.
- **Response-overflow policy:** the **final serialized response** is capped at 8 KiB regardless of method. `recall` returns at most requested `k` results (1 <= k <= 10; default 5), whereas `list_namespaces` may contain up to **32** authorized namespace/count entries; do not apply the recall 10-result cap to namespace listings. Invalid counts, per-record bounds or serialized size require a schema-valid content-free v3 `denied` with `result=null` if representable within the limit, otherwise internal `HOLD` without sending protected bytes. Never truncate records, silently drop entries, stream partial content or invent another wire schema. Verify the final encoding length before releasing any response bytes.
- **Internal `HOLD` versus wire v3:** `HOLD` and `DELIVERY_UNKNOWN` are internal governance/recovery states, **not** H3 v3 response statuses. The only v3 statuses remain `ok`, `not_found`, `denied`. A refusal sent over the wire must be a validated, <=8-KiB `denied` response with `result=null`; if such a response cannot be safely produced, send no protected response and preserve internal `HOLD` with an audit receipt. Never serialize `status=HOLD`, `status=DELIVERY_UNKNOWN`, `result=HOLD` or a fabricated `not_found`.
- Rate limits, bounded concurrent RPC, bounded memory allocation and cancellation timeouts are independent of a correct JSON parser.
- A proof of real server/client identities does not prove absence of data exfiltration through other non-mediated MCP/shell paths. Existing ContinuityOS does not universally intercept external effects.

## 6. Verification matrix — all NOT EXECUTED in R7A1

Each row is a future **test specification**, not an observed PASS. The owner must approve lab boundaries separately before running native Windows tests. `P0` blocks any real-memory integration; `P1` blocks release qualification. Stages: **B0** isolated OS feasibility; **B1** synthetic RPC broker; **C** grants/witness/replay; **D** protected memory reader; **E** adversarial integration.

| ID | Priority | Stage | Stimulus / fixture | Expected result / evidence |
|---|---|---|---|---|
| T01 | P0 | B0 | Actual expected AppContainer client token | Capture real User SID, AppContainer SID, capabilities, integrity and impersonation level; no inferred identity |
| T02 | P0 | B0 | Ordinary same-user desktop process | Denied despite matching User SID; no model-based allow |
| T03 | P0 | B0 | Another AppContainer under same Windows user | Denied on Package SID mismatch |
| T04 | P0 | B0 | Different interactive user or session | Denied; no response content |
| T05 | P0 | B0 | Empty/malformed token, identity-only impersonation | Denied without falling back to process privileges |
| T06 | P0 | B1 | `RpcImpersonateClient` forced failure | Denied, zero memory calls, no privileged fallback |
| T07 | P0 | B1 | `RpcRevertToSelf` forced failure | Thread/process quarantined or stopped; auditable HOLD |
| T08 | P0 | B1 | Repeated calls through one binding | Per-call callback executed and per-call token checked |
| T09 | P0 | B1 | Changed/revoked grant on reused binding | Next call denied, no cached positive decision |
| T10 | P0 | B1 | Unauthorized caller permitted by endpoint-only ACL | Interface ACL still rejects; no dispatch to handler |
| T11 | P0 | B1 | Fake `ncalrpc` listener claims the expected endpoint name or forges/stales a broker challenge | Independently pinned server proof and same-binding freshness fail; trusted client sends **zero H3 application/sensitive request bytes**. Reconnect/restart requires new pre-send proof. Observe zero H3 application bytes from the approved trusted client to the impostor. An untrusted agent's direct/raw RPC bypass is not proof of C0 and cannot obtain protected memory because the broker enforces authority independently; do not claim to stop an attacker sending its own known data |
| T12 | P0 | B1 | Broker replaced/restarted with an unpinned identity or SSP/NTLM gives misleading mutual-auth success | Independently pinned server identity and negotiated provider/binding fail the spoof/downgrade test; the client sends no sensitive H3 application payload before verified proof |
| T13 | P0 | B1 | Alternate RPC protocol/endpoint | No accepted route; prove no unrelated RPC interface |
| T14 | P0 | B1 | 16-KiB cap + one byte via `ncalrpc` | Native frame parser rejects before allocation; do not rely on `MaxRpcSize` |
| T15 | P0 | B1 | RPC-stub declared length overflows integer | Denied before memcpy/unmarshal/alloc; no crash |
| T16 | P0 | B1 | v1/v2 and unknown read method / mutation method | Denied before authority or DB path |
| T17 | P1 | B1 | Unicode C1, bidi controls, escaped equivalents | Rejected in request and response fields as specified by v3 |
| T18 | P1 | B1 | Thai/Cyrillic/Arabic, ZWJ/ZWNJ, combining marks | Accepted within bounds; canonical digest parity preserved |
| T19 | P0 | C | Client-provided `signature_verified=True` | Denied unless independently verified owner signature is available |
| T20 | P0 | C | Forged signature with correct-looking grant fields | Denied; verifier records signature failure only |
| T21 | P0 | C | Unknown, rotated, revoked owner key | Denied/HOLD per pinned key epoch; no auto-enrollment |
| T22 | P0 | C | Grant wrong installation, package or session, or attacker asserts installation via caller token/RPC payload | Signed grant must match separately owner-pinned broker `installation_id`; User SID and Package SID come from current-call OS token. Wrong binding or untrusted installation claim -> `DENY` |
| T23 | P0 | C | Grant missing method/namespace; attempts to widen scope | Denied, no silent defaults/wildcards |
| T24 | P0 | C | Not-before time in future / expired grant | Denied using independently trusted time semantics |
| T25 | P0 | C | Repeat `(installation_id, session_id, request_id, nonce)` using same or newly signed/rotated grant | Exactly one durable atomic replay reservation across grant/key/epoch changes and restart; later attempt denied |
| T26 | P0 | C | Concurrent reservations of same canonical `(installation_id, session_id, request_id, nonce)` under different grant versions | Exactly one winner; grant/epoch metadata cannot divide the uniqueness key; no duplicate disclosure |
| T27 | P0 | C | Crash after nonce reservation before response | Restart recovers HOLD/preserved reservation, not free replay |
| T28 | P0 | C | Copy/backdate replay DB and local witness together | Independent epoch detects rollback or returns HOLD |
| T29 | P0 | C | Independent witness missing/unverifiable, revoked/stale or epoch mismatch; atomic durable attachment of a verified witness receipt to an existing replay reservation fails or crashes | Internal `HOLD` and zero `READ_PLAN`, DB reads or protected disclosure; existing replay reservation remains consumed across restart, no cache fallback/automatic retry. Only independently authenticated witness evidence may be durably attached, and attachment must precede any read |
| T30 | P0 | C | Revocation after successful authorization, before output | Predisclosure recheck blocks bytes |
| T31 | P0 | C | Witness epoch changes mid-read | HOLD, discard candidate response |
| T32 | P0 | C | Agent sends fabricated `BrokerEvidence` / `WitnessEvidence` | Never accepted as verified producer-origin evidence |
| T33 | P0 | D | Agent attempts direct open of DB/WAL/SHM | OS AccessDenied for every protected path and backup |
| T34 | P0 | D | DB symlink/junction/reparse escape | Denied before OS file open; no root bypass |
| T35 | P0 | D | Caller supplies raw SQL, DB path, `ATTACH`, write statement | Interface prohibits request; protected reader cannot execute |
| T36 | P0 | D | Unauthorized namespace/key, listing/`not_found` probing | No distinguishable unauthorized metadata disclosure |
| T37 | P0 | D | Read returns restricted/confidential record | Predisclosure classification denies or redacts, documented policy |
| T38 | P0 | D | Response exceeds 8 KiB; `recall` exceeds requested `k` (1-10); `list_namespaces` exceeds 32 entries | Enforce method-specific limits and final encoded size; no truncation or partial content. Send valid content-free v3 `denied`/null within 8 KiB or remain internally `HOLD` with no protected reply |
| T39 | P1 | D | WAL recovery, concurrent writer, locked DB or I/O failure versus an authorized completed no-hit lookup | Storage failure -> internal `HOLD`, optionally valid content-free wire `denied`/null, never `not_found`; `not_found` only for completed authorized no-hit `find/context`; no corruption and no wire `HOLD` |
| T40 | P0 | E | Separate same-user process attacks broker after startup | End-to-end denial including direct DB, RPC and logs |
| T41 | P0 | E | Forged broker proof plus replayed prior good reply | Client rejects untrusted server and replayed message |
| T42 | P0 | E | Inject power loss before/after replay reservation, before durable disclosure intent, after intent before byte one, mid-response, and after send before terminal receipt | For every phase verify crash-safe replay reservation and **durable intent before any protected byte**. Unknown/partial delivery retains intent as `DELIVERY_UNKNOWN/HOLD`; no silent `NOT_SENT`, no false success or automatic replay. Independent recovery receipts confirm no second disclosure |
| T43 | P1 | E | Denied request includes malicious memory text | No text in response, error or audit logs |
| T44 | P1 | E | Rate spike, request storm, cancellation/timeout | Bounded CPU/memory/threads, no privilege escalation |
| T45 | P0 | E | Same v3 wire on mock vs native broker | Exact schema/digest parity, but native authorization requires OS proof |
| T46 | P0 | E | No authenticated witness/owner grant yet | No positive runtime disclosure even with all Python fixture booleans True |
| T47 | P0 | E | Service SID lacks required DB ACL / process privilege | HOLD, never “repair” by broadening ACL silently |
| T48 | P1 | E | Repeated runs after key rotation and recovery | Stable audit receipts, verifiable epoch transitions, no lost denial |

### Acceptance receipts for every native test

Each execution must record: tested commit and tree SHA; Windows build/patch level; actual test-host identity (redacted), toolchain version, signed test executable digest, exact expected/observed verdict, call-bound token evidence **without token secrets**, service/endpoint ACL digest, bounded timing/resources, crash-resume result, audit receipt hash and independent reviewer verdict. Do not store raw credentials, personal memory, private keys or dangerous runtime tokens in evidence packages.

No native test is considered `PASS` merely because a fixture boolean is `True`; the test must demonstrate that the value originated from a trusted Windows/cryptographic producer.

## 7. Stage gates and owner approvals

| Gate | Prerequisites | Changes explicitly NOT implied |
|---|---|---|
| R7A1 architecture source draft | Exact baseline, complete threat matrix and source-backed assumptions | Creating/writing repo file, git add/commit/push/PR |
| R7A1 repository write | Owner approves **exact new path, expected baseline and file count** | Commit, branch, push, merge, service installation |
| R7B0 executable feasibility | Owner approves disposable test environment, specific binaries, resource/time limits, read-only API probes | Production service registration, TPM/ACL writes |
| R7B1 native synthetic broker | Independent test branch, approved service identity and lab-specific ACL changes | Real memory reads or production deployment |
| R7C authority and replay | Verified owner keys, distinct witness/replay custody, revoke/crash test suite | Treating caller-supplied dataclasses as proof |
| R7D memory reader | All P0 OS identity/grant/replay gates green, protected DB/WAL DACL, data classification | Broad SQL or unconstrained memory export |
| R7E integration | Adversarial suite, independent reviewer, no P0 bypass, auditable rollback | Automatic production permission |
| R7F production candidate | A new explicit owner approval and reproducible exact-effect plan | Implicit activation merely because tests passed |

**STOP on:** SHA/TREE drift; unexpected file/write scope; privileged fallback; actual RPC token mismatch; witness/replay ambiguity; grant signature error; absent AppContainer proof; unverified server identity; DACL bypass; logging of protected content; inability to prove rollback; compiler/toolchain substitution; missing exact owner approval. Keep production `HOLD` at all prior gates.

## 8. Open technical decisions (must not be silently defaulted)

1. **Real AppContainer token shape:** current model hardcodes Low IL and zero capabilities; verify with Windows API on the actual client before adopting or revising the profile.
2. **Broker proof method:** choose a genuinely authenticated server identity and challenge binding; decide whether to use Windows-authenticated principal, dedicated sealed key, or both; do not invent key custody.
3. **Service SID and OS host:** dedicated low-privilege identity vs restricted service SID must be tested with selected SCM/service configuration; no real service changes authorized yet.
4. **Grant format and time source:** determine canonical signature envelope, key rotation policy, expiry/rollback handling and absence of runtime automatic key creation.
5. **Witness and replay isolation:** define distinct failure domains and recovery; TPM anchor or another independently trusted authority requires its own security gate.
6. **Read-only memory data classification:** define which namespaces/records may be shared and what an owner-approved disclosure actually means.
7. **Native compiler:** at last local inspection `midl.exe` and `cl.exe` were not found on PATH; this is not proof they are uninstalled. R7B0 must discover exact installed toolchain before choosing a build workflow.
8. **Disk headroom:** C: had approximately 13.76 GiB free at last observation; measure again before downloads/builds and keep strict storage budgets.
9. **Git workflow:** owner-authorized R7A1 created this one Markdown file in the independently cloned detached baseline; R7A2 and R7A3 repaired it locally, and R7A4 authorizes only this in-place documentation repair. It remains the sole untracked file; git add, commit, branch mutation, push, PR and merge are not authorized. All 14 preexisting worktrees and their 181 untracked artifacts remain protected.

## 9. Source references and traceability

**Source-derived from exact Git baseline:**

- [`continuityos/h3/readonly_contract.py`](https://github.com/bitmaster162/continuityos/blob/c2b2a3ed1ddd7a2d8b39ff16e3e6d9b8ce419f90/continuityos/h3/readonly_contract.py)
- [`continuityos/h3/authz_decision.py`](https://github.com/bitmaster162/continuityos/blob/c2b2a3ed1ddd7a2d8b39ff16e3e6d9b8ce419f90/continuityos/h3/authz_decision.py)
- [`docs/H3_R6A_OFFLINE_CONTRACT.md`](https://github.com/bitmaster162/continuityos/blob/c2b2a3ed1ddd7a2d8b39ff16e3e6d9b8ce419f90/docs/H3_R6A_OFFLINE_CONTRACT.md)
- [`README.md`](https://github.com/bitmaster162/continuityos/blob/c2b2a3ed1ddd7a2d8b39ff16e3e6d9b8ce419f90/README.md)

**Windows API facts externally verified against Microsoft Learn:**

- [RpcServerRegisterIf3 — interface ACL, AppContainer default and ncalrpc `MaxRpcSize` exception](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterif3)
- [RPC interface registration flags — `RPC_IF_SEC_NO_CACHE`, `RPC_IF_ALLOW_SECURE_ONLY`](https://learn.microsoft.com/en-us/windows/win32/rpc/interface-registration-flags)
- [RpcImpersonateClient — non-success and privilege fallback](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcimpersonateclient)
- [RpcRevertToSelf](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcreverttoself)
- [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
- [TOKEN_INFORMATION_CLASS — AppContainer and capabilities](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [RPC_BINDING_HANDLE_SECURITY_V1 — default server authentication limits](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_binding_handle_security_v1_a)
- [Secure RPC client/server design](https://learn.microsoft.com/en-us/windows/win32/rpc/writing-a-secure-rpc-client-or-server)
- [Service SID type and restricted service conditions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/ea1a9acd-4bb2-473f-ae5b-55969c5960fc)

**Final classification:** `R7A1 WRITE PASS / R7A2 REPAIR PASS / R7A3 REPAIR PASS / R7A4 OWNER-APPROVED LOCAL DOC REPAIR / UNTRACKED / NO COMMIT / NO REAL BROKER / NO LIVE EVIDENCE / PRODUCTION HOLD`.
