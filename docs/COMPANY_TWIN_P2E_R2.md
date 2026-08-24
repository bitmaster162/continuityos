# Company Twin P2E-R2 — Selected Google Drive self-pilot

P2E-R2 is a controlled, read-only self-pilot that proves a single selected Google Drive artifact can enter the Company Twin pipeline without turning ContinuityOS into a general Drive crawler or persisting private Drive identifiers.

## Exact source boundary

The pilot is intentionally limited to one selected folder and one `index.html` artifact containing the ContinuityOS adversarial-analysis document. The committed fixture contains a SHA-256 locator hash and sanitized publication/content fields only. It does **not** contain the raw Google Drive folder ID, file ID, Drive URL, owners, sharing metadata, permissions, comments, email addresses, OAuth material, credentials, or tokens.

The connector identity is therefore represented as:

`selected source identity -> out-of-band SHA-256 locator -> sanitized fixture -> P2B envelope`

The underlying Drive identity is never reconstructable from repository data.

## Pipeline

`selected Drive artifact -> sanitizer -> P2B canonical ingestion -> P2A replay -> P2C policy -> P2D Operating Console`

The package code performs no live Drive/API/OAuth/network calls. Live Drive access is outside the package and was used only to select and inspect the one approved source before producing the redacted fixture.

## Truth model

The ingested source record remains `EVIDENCE`. P2E-R2 projects only explicit source facts:

- the document title and publication date stated by the sanitized source;
- the selected snapshot's source-modification timestamp;
- a bounded observation describing the document's explicit subject matter.

No merge decision, approval, business rationale, causal conclusion, or automatic `INFERENCE` is created from this document.

## Security invariants

- exactly one source locator hash is allowlisted;
- exactly one folder title, one file name, and one MIME type are accepted;
- arbitrary Drive IDs or URLs are not accepted as public output fields;
- owner/sharing/permission/email/OAuth/credential-like metadata fails closed;
- Drive-host URLs, email-like values, bearer/OAuth token shapes, and private-key material fail closed;
- unknown safe fields are discarded rather than copied through;
- sanitized content digest is recomputed deterministically;
- re-ingest is idempotent;
- ACL is fixed to `TEAM / team:engineering`;
- source actor is `SERVICE / READ_ONLY`;
- Research Robot remains bounded to `READ/PROPOSE`; `APPROVE` and `EXECUTE` are denied/absent through the existing P2C/P2D policy plane.

## Non-goals

P2E-R2 does not provide recursive Drive discovery, general Drive ingestion, Gmail/Slack ingestion, private/customer ingestion, OAuth storage, deployment, runtime cutover, canonical-memory mutation, model lifecycle changes, robot execution, trading, or capital authority.

## Qualification

The candidate must pass clean-source, wheel-only, editable/full regression, governance/hardening, P0 and CodeQL on the exact PR head before any separate merge approval may be considered.
