# ContinuityOS H3-R6B5 R1 — strict evidence types, preserving wire v3

**Status:** local candidate / offline synthetic contract only / production HOLD.
**Approval:** exact owner-authorized H3-R6B5 R1 on 2026-10-11.
**Compatibility:** wire v3 unchanged; the earlier v2 to v3 transition
remains deliberately incompatible and documented below.
**Authority ceiling:** edit only 3 approved existing files in the local
branch; no new files, commit, push, PR, merge, deploy, real IPC, DB, TPM,
MCP, Scheduler, Windows service changes or real-memory operations.

## Protected Git and local worktree custody

- Repository: bitmaster162/continuityos.
- Protected master HEAD: fe06d8c769076ea4a1edd0ece6fc88ffa0102a2c.
- Protected tree: 77b264aa4e1e5825b3752a8cc0da0c80e8ba36f5.
- Branch: agent/h3-r6a-offline-contract-r1.
- Local worktree:
  C:\Users\coins\AppData\Local\ContinuityOS\h3-r6a-offline-contract-20261011.
- Accepted source: recovery-r11-20261009T184302Z/source, remains clean.
- Protected offline R16-D10 worktree:
  r16-d10-memory-offline-20261010, retains its 29 untracked artifacts.

Exactly three existing untracked files are approved for H3-R6B5 changes:

1. continuityos/h3/authz_decision.py
2. tests/test_h3_r6a_authz_decision.py
3. docs/H3_R6A_OFFLINE_CONTRACT.md

The other three files must retain their exact H3-R6B4 SHA-256:

- continuityos/h3/__init__.py:
  8e6c4af2af11e2a6a4eef08ab59a558be2950acaf95499ba45465ce2f2ba1480
- continuityos/h3/readonly_contract.py:
  0bb4255f957ce85e5f3eb0e6291c155cddd60d9613affc47a319b03f65daa918
- tests/test_h3_r6a_readonly_contract.py:
  eead6cfffaa8ced0401cd031e420231847cc7a673769b8e855416f29db7c4d17

Historical note: H3-R6B3 changed readonly_contract.py, its test, and
this document. That is not the present H3-R6B5 write authority.

No source or production file outside this worktree may change.

## Scope and history of the draft interface

H3-R6A created a pure offline contract and model for read-only memory
queries. H3-R6B1 upgraded draft v1 to v2, rejecting unvalidated direct
ReadonlyRequest objects, adding concrete grant.session_id, distinguishing
denied/not_found/ok, and binding responses to protocol/request_id/
session_id/nonce/method.

H3-R6B2 independent source review found a P2 gap: an otherwise
well-formed response from a recall/context request could match another
request with the same five identifier fields while having a different
query, namespace or k value. This is a synthetic contract problem;
no real RPC broker existed and no live data breach was demonstrated.

H3-R6B3 introduces draft protocol continuityos.h3.ipc/v3. Older
v1 and v2 requests and responses must be explicitly rejected.
No compatibility fallback, negotiation or silent conversion is allowed.

## v3 request and canonical digest specification

A v3 request contains exactly:

- protocol: continuityos.h3.ipc/v3
- request_id: bounded ASCII ID (1-64 characters)
- session_id: bounded ASCII ID (1-64 characters)
- nonce: 32-64 lowercase hexadecimal characters, caller-supplied
- method: one of the five read-only method names
- params: exact per-method bounded parameter dictionary

Allowed calls:

| Method | Required params | Optional params |
|---|---|---|
| memory_status | none | none |
| list_namespaces | none | none |
| find | namespace, key | none |
| recall | namespace, query | k |
| context | namespace, query | k |

For content calls, namespace is required and never a wildcard.
Key maximum is 128 Unicode scalar characters. Query maximum is 2048.
k is an integer in [1, 10], not boolean; omitted k and explicit k=5
are distinct canonical requests, even when semantically equivalent.
Mutating methods are not in the allowlist.

The v3 request_sha256 is the SHA-256 of:

    DOMAIN_PREFIX || CANONICAL_REQUEST_UTF8

DOMAIN_PREFIX is the exact byte string:

    b"continuityos.h3.canonical-request.v3\x00"

CANONICAL_REQUEST_UTF8 is the JSON encoding of the complete validated
request, including protocol, request_id, session_id, nonce, method
and every parameter (including presence/absence of optional params).
The canonical serialization uses:

- JSON object keys sorted recursively, not insertion order.
- Comma and colon separators without whitespace.
- UTF-8 output with ensure_ascii=False and allow_nan=False.
- Only accepted scalar types; no duplicate JSON object fields.
- No Unicode normalization; accepted code points are retained.
- Invalid UTF-8, unpaired surrogate code points and JSON constants
  NaN/Infinity are rejected.
- Parameter pairs must have unique names in canonical sorted order;
  direct dataclass construction and later mutation are revalidated.
- The complete canonical encoded request is capped by MAX_REQUEST_BYTES.

The hash is lowercase hexadecimal, exactly 64 characters.
This is a domain-separated *public integrity consistency* digest, NOT
a signature, MAC, channel binding or proof of origin. Neither the
domain prefix nor SHA-256 keys the response to a trusted principal.

## v3 response: exact request-to-response binding

Every v3 response contains exactly EIGHT fields:

- protocol
- request_id
- session_id
- nonce
- method
- request_sha256
- status
- result

The first five fields must match the validated request exactly.
request_sha256 must be a lowercase 64-character hex string equal to
the recomputed domain-separated digest of the ENTIRE request.
Missing, malformed, uppercase or mismatched digests are rejected,
including for denied and not_found responses, before response data
can be consumed. Extra or duplicate fields are rejected.

A changed query, namespace, k, explicit/omitted optional parameter,
find key, request_id, session_id, nonce or method necessarily alters
the canonical hash. The digest comparison detects substitution when
the verifier has an independently established reference request.

The parser returns ReadonlyResponse(status, result) with three
explicit statuses:

- ok: authorized, scope-checked synthetic result.
- not_found: only find/context, scope must be valid; result=null.
- denied: refusal; result=null even if authorized scope is empty.

DENIED must never leak metadata or text. It can be generated without
any authorized namespace. NOT_FOUND requires a verified scope and is
never a replacement for a failed authorization.

Allowed ok result shapes remain:

- memory_status: exact {available: bool}.
- list_namespaces: <=32 distinct {namespace, count} entries within scope.
- find: exact {namespace, key, text}; key/namespace bound to request.
- recall: <=k exact {namespace, key, text} results, each requested scope.
- context: exact {namespace, text}, requested scope.

Limits in pure JSON functions: request <=16 KiB, response <=8 KiB.
The size limits are NOT transport-level resource protection. This
module does not implement an RPC buffer cap, timeouts or memory allocation
policies for an actual service.

## Negative regression targets

The two pre-existing unittest files exercise:

- Wire version v3 and explicit rejection of v1/v2;
- canonical hash equality for differently ordered parameter keys;
- canonical hash mismatch for recall query, namespace, k, omitted k;
- canonical hash mismatch for context query and find key;
- all three statuses include request_sha256;
- missing, malformed, incorrectly cased and incorrect digests denied;
- duplicate JSON fields, hidden identity injection, raw metadata leaks;
- cross-session replay of a response (different session), wrong nonce,
  wrong method and invalid direct Python dataclass mutations;
- revoked witness, forged owner grant, mismatched session/nonce replay,
  AppContainer identity, unknown/malformed evidence and strict DENY;
- no successful real authorization claim from synthetic MODEL_ALLOW.

Run only the scoped tests from the exact worktree with bytecode writes
disabled. PYTHONPATH should make the local project importable:

    python -B -m unittest discover -s tests -p "test_h3_r6a_*.py" -q

The prior R6B2 run under Python -I failed import because isolated mode
removed the local source path. That failure was an import-environment
issue, not an application logic failure. R6B3 runs use Python -B with
the exact local checkout as working directory, not -I.

No test accesses real DB, TPM, RPC, Windows tokens, remote APIs or
production memory. No test-output files are created inside the project.

## H3-R6B5 R1 — equality forgery and fail-closed evidence hardening

The independent H3-R6B4 review detected 34 reproductions of unsafe
Python comparison semantics inside authz_decision.py: 17
non-string values whose __eq__/__ne__ always indicated equality
were accepted as identity/authority attributes (MODEL_ALLOW), and
17 values whose comparisons raised RuntimeError escaped the denial
path. These attacks were on synthetic dataclasses in memory and
did not compromise real Windows IPC, because no live broker exists.

R6B5 now checks exact builtin primitive types BEFORE comparison:

- BrokerEvidence: 1 plain-string origin, 6 exact boolean flags.
- TransportEvidence: 1 plain-string protocol, 7 exact boolean flags.
- ClientEvidence: 5 plain-string identity fields, 3 exact boolean
  flags, 1 tuple field for capabilities (must remain empty).
- GrantEvidence: 5 plain-string identity/session fields, 3 exact
  boolean flags, 2 tuple fields for methods/namespaces, with each
  member separately checked as a plain string.
- WitnessEvidence: 1 plain-string origin, 4 exact boolean flags.
- ReplayEvidence: 4 plain-string identity fields, 2 exact flags.

In total, 17 string + 25 boolean + 3 tuple fields are guarded.
Subclassed str values, AlwaysEqual impostors, raises-on-comparison
objects, non-bool truthy values, malformed tuple contents and
uninitialized dataclass objects must lead to deterministic DENY
before equality, regex/set membership or allocation decisions.

The top-level AdmissionEvidence container's nested fields are now
accessed inside a fail-closed exception boundary: an incompletely
allocated dataclass receives UNVERIFIED_EVIDENCE_TYPE rather than
an escaping AttributeError. An incomplete nested evidence instance
must produce its respective type-appropriate DENY reason. Policy and
ReadonlyRequest remain subject to their previous strict validation.

This is a **structural type check, NOT an authenticity check**.
Untrusted Python callers can still fabricate fully type-correct
BrokerEvidence, GrantEvidence, WitnessEvidence or ReplayEvidence
with all required booleans True; the model can return MODEL_ALLOW
for such a synthetic fixture. An actual broker must source proof
exclusively from independently verified OS/cryptographic boundaries
and never accept caller-created evidence as runtime authority.

No wire changes are made in R6B5. Protocol
continuityos.h3.ipc/v3 and its canonical full-request digest are
unchanged. The digest remains publicly forgeable; it is not a
message authentication code, signature, trusted channel or replay
protection mechanism.

Test coverage adds the R6B5EvidenceTypeHardeningTests class inside
the pre-existing authorization test file. It checks 17 string
fields against AlwaysEqual, raises-on-comparison and subclassed
strings; 25 bool fields and 3 tuple fields against malicious
objects; incomplete top-level and nested instances; crafted grant
tuples; mutated owner policy; and a still-positive all-plain-string
synthetic model result (to avoid misrepresenting type checks as
verified authorization).

## Remaining unimplemented security boundaries

This stage does not build a real broker or grant runtime permissions:

1. No distinct Windows security service principal or protected service
   owner, no real service identity and no enforced DACL isolation.
2. No secured, authenticated ncalrpc endpoint, runtime client token
   extraction, impersonation, RevertToSelf or independent server proof.
3. No verified owner signature, non-exportable key, pinned service
   manifest, signing ceremony, key rotation or TPM provisioning.
4. No independent external monotonic witness, nonce store or real
   per-call replay protection.
5. No real SQLite/WAL reads, confidential output classification,
   protected memory service or proven no-direct-DB access.
6. No real memory disclosure, operating-system stress or integration
   testing and no authorization for production activation.

An adversary that can build a new response with matching identifiers
can compute the same public request_sha256 and forge a syntactically
valid response. The exact same request/response pair can also be
replayed without the future independent nonce store. SHA-256 does not
remove these risks. In particular, a MODEL_ALLOW based only on
caller-supplied dataclasses is still NOT runtime permission.

## Completion criteria and STOP gates

- Exactly 3 approved R6B5 files changed relative to verified
  H3-R6B4 SHA-256, and only within the existing local worktree.
- __init__.py, readonly_contract.py (wire v3), and its test file
  remain byte-for-byte unchanged.
- Six total untracked files remain; staged=0; tracked modified=0.
- Exact branch/HEAD/TREE unchanged from protected source baseline.
- Accepted source and D10 untouched; D10 retains 29 untracked items.
- Local bounded offline regression and independent negative probes
  must pass, including all 34 original H3-R6B4 reproductions.
- No commit, push, PR, merge, deploy, live IPC, DB, TPM or Scheduler.
- A new independent security defect means REVISE/STOP before commit
  eligibility, regardless of previous green unit tests.

Maximum status permitted:

    H3-R6B5 LOCAL OFFLINE MODEL PASS
    LIVE BROKER UNIMPLEMENTED
    PRODUCTION HOLD
