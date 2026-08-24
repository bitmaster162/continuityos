# Company Twin P2E-R3 — selected internal core one-file pilot

## Scope

P2E-R3 extends the Company Twin self-pilot from public GitHub history and one small redacted Drive artifact to one larger internal knowledge source: `ContinuityOS_Core.md`.

The boundary remains deliberately narrow:

- exactly one selected internal Markdown source;
- no Drive-wide or recursive crawl;
- no live Drive, OAuth, Gmail, Slack or customer connector in package code;
- no raw provider file identifier or provider URL in the committed fixture;
- no owner, sharing, permission, comment, email or credential metadata;
- no merge, deploy or runtime transition in this work order.

The selected provider locator is hashed outside the committed fixture. The repository stores only the SHA-256 locator hash.

## Sanitized source model

The original internal file is approximately 111 KB. P2E-R3 does **not** commit the full source. It commits one bounded sanitized excerpt that preserves a small set of source-attributable statements and headings needed to test institutional-memory ingestion.

The sanitizer:

1. enforces the exact selected file name and MIME type;
2. requires the exact precomputed locator hash;
3. validates source observed/modified timestamps;
4. rejects sensitive provider metadata keys;
5. rejects email, credential/token shapes, private-key markers and Google Drive/Docs hosts in persisted text;
6. normalizes Markdown deterministically;
7. proves the committed excerpt is smaller than the source size;
8. computes a deterministic sanitized document digest.

Unknown non-sensitive fields are discarded rather than persisted.

## Deterministic Markdown chunking

The sanitized Markdown is split into bounded chunks using deterministic paragraph/heading breakpoints.

Each chunk records:

- stable ordinal-based `chunk_id`;
- `chunk_index` and `chunk_count`;
- parent-document SHA-256 digest;
- hashed parent source locator;
- source-relative character range;
- heading lineage;
- chunk SHA-256 digest;
- bounded text.

Stable chunk object IDs are based on the selected source hash plus ordinal. A new sanitized document revision keeps those object slots stable while deriving a new revision ID from the new parent-document and chunk digests, allowing P2B supersession semantics.

## P2B → P2A → P2C → P2D

Each chunk becomes one P2B envelope with:

- `SERVICE / READ_ONLY` actor;
- `TEAM / team:engineering` ACL;
- hashed `drive-sha256:` source reference only;
- no live connector dependency.

Re-ingesting the exact same document is idempotent.

P2A projects the chunk records as `EVIDENCE`. It adds only explicit facts about the selected document snapshot and retained source-section lineage. It does not generate decisions, outcomes, causal rationale or `INFERENCE`.

P2C remains the authority boundary. Engineering and the bounded Research Robot can read the engineering-scoped evidence; Operations cannot. The Research Robot remains `READ/PROPOSE` only with `APPROVE/EXECUTE` denied.

P2D consumes the resulting memory through the existing read-only Operating Console.

## Security and authority invariants

```text
SOURCE_FILES_ALLOWED=1
RECURSIVE_DRIVE_CRAWL=FALSE
RAW_PROVIDER_IDS_COMMITTED=FALSE
RAW_PROVIDER_URLS_COMMITTED=FALSE
OAUTH=NONE
LIVE_CONNECTOR_IN_PACKAGE=FALSE

AUTO_INFERENCE=FALSE
AUTO_DECISION=FALSE
AUTO_APPROVAL=FALSE

AGENT_READ=BOUNDED
AGENT_PROPOSE=BOUNDED
AGENT_APPROVE=DENY
AGENT_EXECUTE=DENY

DEPLOY=NONE
RUNTIME_EFFECT=NONE
CAN_TRADE=FALSE
CAPITAL_PERMISSION=DENY
```

## Qualification

Before merge consideration the exact PR head must pass:

- exact-index secret scan;
- clean source tests;
- built-wheel external-site-packages tests;
- editable full suite;
- governance regression;
- release hardening;
- Linux symlink/realpath gate;
- P0 Unified Shadow Continuity;
- CodeQL;
- Ubuntu and Windows required review gates.

A failed candidate is fixed with a new commit and fresh natural CI. Failed workflows are not manually rerun to manufacture qualification.

## Non-goals

P2E-R3 does not authorize:

- merge without a separate exact-head approval;
- local install/start or deployment;
- R21H runtime/model/canonical-memory/admissions mutation;
- broader Drive access;
- Gmail/Slack/customer ingestion;
- robot execution;
- trading or capital authority.
