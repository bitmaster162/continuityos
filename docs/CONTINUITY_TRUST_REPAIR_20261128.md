# Continuity trust repair — 2026-11-28

**Scope:** bounded repository repairs for core Memory, Continuity, the retrieval-based Twin, and their existing product entrypoints. This is an unreleased review candidate. Person production admission remains **HOLD**.

## Evidence identity and decision

Implementation began from a verified clean Git baseline:

- Repository: `bitmaster162/continuityos`.
- Baseline commit: `cc889675df6e54cf7caa759e9aca6b032c217429`.
- Baseline tree: `36fdb7de3a08c457056ccdbb1830c7fba8af2232`.
- Repair branch: `robert/continuity-trust-20261128`.
- Authorization: the project owner requested implementation of the proposed audit repairs. This authorizes this reviewable repository package, not global operational activation.

The [Person acceptance matrix](PERSON_TWIN_ACCEPTANCE_MATRIX_20261128.md) and its [source bindings](person_twin_acceptance_matrix_20261128.json) retain that original baseline. The matrix maps twelve acceptance families to 29 source files. It separates existing implementation, historical test narratives, new candidate validation and missing production evidence. In particular, A3 publication-result disambiguation and the durable admission wiring in Demo R2 already exist in the baseline; this repair does not recreate or claim to have implemented them.

## Behavior delivered

| Surface | Previous failure or ambiguity | Candidate behavior |
|---|---|---|
| Token budgeting | A local context-size calculation could initialize an installed provider SDK and send memory when credentials existed. | Token counts, context packing and cost estimates stay local by default. A provider call requires an explicit per-call opt-in, provider/model pairing, data-scope declaration and the current effect check. |
| Extraction | Messages could be merged before role filtering; source ownership and model confidence were overstated. | Roles are filtered before processing. Extraction occurs per source message, preserves source/time/span identities and emits unreviewed candidates with no numeric confidence. |
| Deduplication | A top-ranked fuzzy match could suppress distinct source observations. | Extracted candidates use exact source-bound keys and checked writes. Same text from different sources survives; retired candidates are not resurrected by reimport. |
| Current memory | Retired/future/foreign rows could consume the retrieval limit or appear in context. | Temporal, candidate and scope predicates run before both candidate-ranking limits. Context defaults to current records and includes stable local IDs and review labels. |
| Writes | Item/FTS, supersession and version checks could commit separately. | Managed writes use one SQLite transaction, nested savepoints and checked versions under the write lock. Failed COMMIT/rollback recovery has explicit suspended/unknown outcomes without automatic retry. |
| Continuity | Closing a loop removed its identity; unrelated state could mix; successful completion looked unhealthy. | Closure retains its first result/proof/history. Scoped state, ACTIVE/PAUSED/DONE and one shared health assessment are used by doctor and product status. |
| Handoff | Mandatory canon/loops could be silently sliced. | Structured handoff includes all applicable state and recorded closures, stable references, counts and a scope-bound digest. A caller budget that cannot fit the payload returns HOLD with no partial payload. |
| Retrieval Twin | Similarity was presented as behavioral confidence; absence of conflict looked like permission. | Evidence, candidates, provenance, scope, uncalibrated retrieval signals and explicit unknown/no-evidence outcomes replace those claims. The method name `predict` remains for compatibility. |
| Product integration | CLI, boot, MCP reminders and exported agent rules used independent historical/raw views. | These consumers use current scoped selection; boot is read-only, resource handles are closed, overflow is visible and rule exports omit candidates and retired rules. |
| Model budgets | Static prices and effective-context numbers were described as research-backed facts. | Legacy settings remain compatible but are explicitly unverified/uncalibrated. Caller budgets can be supplied; unknown model pricing fails instead of inheriting another model's price. |

These changes do not create a new memory subsystem or replace protected Person/R21H contracts.

## Source provenance and candidate handling

The default extraction import accepts the `user` role. Missing authors remain `unknown`; they are not silently promoted to `user`. A caller can explicitly choose a different role set. Excluded messages are not passed even to an explicitly supplied LLM callable.

Each extracted candidate records source/vendor, conversation identity/title, exported message ID when available, parser record ordinal, export-relative filename, source time and its origin, input digest, exact spans and their hashes. The export digest is labelled `NORMALIZED_PARSED_JSON_SHA256`: it is not a claim about the original file's bytes. Derived identities and conversation-time fallbacks are also labelled as such.

LLM-produced candidates must point to valid spans in the actual input. The bounded model input exposes `input_length`, `inspected_length` and `input_truncated`. Span validation proves that the cited text occurs in the input; it does not prove that a paraphrase follows from that text. Therefore even a valid candidate has:

```json
{
  "confidence": null,
  "review_status": "UNREVIEWED",
  "admission_status": "CANDIDATE",
  "accepted": false
}
```

`extraction_signal` is a count of marker matches or verified spans, with an explicit `score_kind`. It is not a probability. A proposed semantic `type: fact` does not mean an accepted fact. Human acceptance, authentic author identity and external authority remain separate processes.

Raw Memory recall can return candidates for inspection. The repaired canon, current operational views, Twin accepted-evidence view and rules export exclude explicit candidate/rejection markers. Manual legacy entries remain `RECORDED_NOT_VERIFIED`, rather than becoming authenticated facts. Direct metadata or SQL writes are outside any source-authentication guarantee.

## Scope, time and completeness

`Continuity(memory, project=..., subject=...)` and `Twin(memory, project=..., subject=...)` select exact local context. Default unscoped Continuity/Twin select legacy unscoped records, not every project. Canon and operating rules can include global records alongside exactly matching scoped records. Loops, frontiers and checkpoints are exact-scope state.

Scope selects data; it is **not** an ACL, authenticated owner identity, grant or production tenant boundary. The protected Person APIs retain their own identity/consent/admission contracts. Public raw Memory APIs remain available. Memory `recall(scope=...)` supports explicit selection; an omitted Memory scope preserves the existing unrestricted search API.

When a trusted scoped Continuity object is supplied to governance preflight, its scope is bound into a distinct context-digest scheme and used for canon retrieval. Action metadata cannot choose this scope. The legacy executor refuses these new scoped receipts using the authoritative ledger payload, even if a caller removes or forges the response's context field. This patch adds no scoped execution authorization; unscoped context fingerprints remain compatible.

Current reads exclude superseded, inactive, revoked, rejected, deleted, expired, future and malformed temporal records. Validity is half-open: `valid_from <= now < valid_to`, with an absent end unbounded. `as_of` remains a historical query. `find` and pointer APIs continue to mean the latest keyed row; they do not acquire the temporal-current contract of `recall(current_only=True)`.

`handoff_snapshot()` returns:

- current applicable canon, latest frontiers, open loops and latest checkpoint;
- recorded closed-loop outcomes;
- counts, excluded-candidate counts, scope and stable local memory references;
- a digest over canonical schema/scope/payload/candidate-count bytes;
- explicit completeness, overflow and authority fields.

Optional `max_items` and `max_bytes` are caller budgets, not universal thresholds. The byte limit measures canonical payload UTF-8, excluding the response metadata envelope. Overflow returns `payload: null`, `complete: false`, `status: HOLD`; it does not return a silently incomplete mandatory context. The digest proves local byte binding, not source authenticity or permission to execute a checkpoint's next action.

Retrieval Twin remains top-k and explicitly non-exhaustive. Its `NO_HEURISTIC_CONFLICT_FOUND` means only that retrieved wording did not trigger the negation heuristic. It is not semantic compatibility, behavioral validation or execution permission. A governance caller still has its separately configured deterministic policy; this patch does not turn the Twin into a complete policy solver.

## Transaction and recovery contract

Managed Store writes are serialized with `BEGIN IMMEDIATE`; nested writes use savepoints. An operation commits only a transaction it owns. Item/FTS insertion and supersession close/new-row updates are atomic within that local database. Checked writes perform version comparison and mutation in the same unit.

Simple readers take the connection lock. Composed recall, handoff and Twin reads use one `Store.read_snapshot()` to avoid mixing a keyword result from one state with a semantic result from another. Writes through Store are refused inside that read scope. The effect ceiling is checked inside the write lock before work and immediately before an owned COMMIT.

There are three distinct outcomes:

1. **Known rollback:** the original exception propagates after managed rollback succeeds.
2. **Unknown COMMIT:** a failed COMMIT acknowledgement after the transaction ended raises `StoreOutcomeUnknown`. The Store suspends; inspect durable state through a fresh connection before deciding any next action.
3. **Unverified recovery:** rollback/savepoint recovery failure raises `StoreRecoveryFailed`, a subtype of the unknown outcome, and suspends the Store.

Neither unknown outcome performs a retry or reports success. This is local SQLite transaction handling, not distributed exactly-once delivery, storage hardware qualification or protection against an operator rewriting the database. Direct access through `store.con` bypasses managed concurrency. A caller-owned raw transaction requires exclusive same-thread use until its commit/rollback; use `store.transaction()` for shared Store instances.

## Health and lifecycle

`doctor()` and `cos status` use `assess_continuity_health`. Check names now describe observations: `memory_nonempty`, `canon_present`, `proof_reference_present`. A proof path/URL is a reference; no external file contents, provider result or signature is verified by these health checks.

- ACTIVE checks the configured frontier/freshness policy. Zero open loops is allowed.
- PAUSED preserves recorded state without requiring active work or continuing checkpoint freshness.
- DONE additionally requires no open loops; it does not require inventing new work.

The legacy defaults of seven open loops and 48 hours are configurable local policy. They are not empirical universal limits. Status reports the chosen policy and suppresses its actionable next-step field for PAUSED/DONE; the checkpoint still retains historical recorded text.

`cos status` preserves the existing immutable/quiescent read behavior and refuses a busy SQLite image. Its total count includes all records; `scoped_count` covers vector-backed records used by Continuity. Malformed/non-object metadata returns HOLD rather than being replaced with an empty/global identity. JSON schema name and major fields remain compatible, but check identifiers and semantics intentionally change.

## API and CLI migration

Examples use caller-selected names and budgets, not recommended global limits:

```bash
cos --db memory.db checkpoint --project demo --subject owner --summary "review ready" --next "" --proof "repo:commit" --lifecycle PAUSED
cos --db memory.db handoff --project demo --subject owner --json
cos --db memory.db handoff --project demo --subject owner --json --max-items 1
cos --db memory.db loop --project demo --subject owner --close 12 --result "reviewed change" --proof "repo:commit"
cos status --db memory.db --project demo --subject owner --json
```

The small handoff budget intentionally demonstrates a nonzero HOLD when the complete payload cannot fit. The loop command only closes an existing loop in the selected scope and preserves first closure evidence.

Compatibility changes to review:

- Extraction `confidence` becomes `None`; use `extraction_signal` only as its documented uncalibrated count. `min_confidence` is a deprecated signal-threshold alias; `min_signal` is the new name.
- LLM extraction output without valid source spans falls back to the offline heuristic. Explicit LLM callables can run during dry-run; dry-run promises no Memory writes, not absence of a caller-supplied model call.
- Unknown roles are excluded by default. Extraction dedup is source-sensitive; raw import retains its previous content dedup behavior.
- Default context becomes current-only. Query historical state explicitly when required.
- Handoff text type and product-status top-level schema remain compatible. Structured handoff is additive. CLI missing/foreign loop closure and budget overflow now return nonzero status.
- Read-only CLI/boot paths require an existing database and close their handles; they do not initialize missing state.
- Import dry-run opens an existing database read-only or uses an ephemeral in-memory store when the selected target is absent. Unsupported legacy preview schemas return HOLD without migration; optional FastEmbed is not initialized for preview.
- Direct legacy CLI use now shares the local default embedding behavior of the packaged entrypoint. An existing database created with optional embeddings requires the explicitly selected matching embedder; this patch does not migrate/re-embed its vectors.
- Twin no longer returns invented `confidence`; callers must read evidence/coverage/status. Manual records do not become verified evidence through migration.
- Unknown cost-model IDs raise `UNCONFIGURED_MODEL_PRICING`. Returned cost values identify unverified static rates. `compaction_policy()` exposes the basis; `compaction_threshold()` remains an integer compatibility view.

Remote token counting is an explicit content disclosure, not a consequence of installing an SDK:

```python
count = memory.estimate_tokens(
    text,
    model_id=configured_model_id,
    allow_network=True,
    provider="anthropic",
    data_scope="exact caller-approved data scope",
)
```

The caller must verify the provider/model configuration and scope. The declaration does not grant authority and cannot override the current-session effect ceiling. Default calls omit these options and remain local.

## Validation

Validation environment: Linux, Python **3.12.14**, pytest **9.1.1**, build **1.5.0**. The source environment included cryptography **50.0.1**. Tests use temporary/synthetic databases and recording/fake clients; they do not qualify the owner's runtime or live models. Skips remain unexecuted cases.

| Verification | Observed result |
|---|---|
| Full source pytest, with no installed package metadata | **3017 passed, 34 skipped, 870 subtests passed**; pytest duration **88.85 s**, command exit **0**. |
| Wheel build | `continuityos-0.10.3-py3-none-any.whl` built successfully as an unreleased review artifact. This is not a new published package. |
| Isolated installed wheel | **2883 passed, 136 skipped, 870 subtests passed**; pytest duration **65.85 s**, command exit **0**. Import came from the fresh environment's `site-packages`; the source checkout was absent from `sys.path`. |
| Compilation and whitespace | `compileall` for source/tests and `git diff --check` passed. |
| Exact staged index secret scan | **PASS**, zero findings across **759** entries; one pre-existing explicit benchmark fixture allowlist. Build products and temporary evidence are excluded from Git. |

The full source command was `python -m pytest -q -p no:cacheprovider`, captured by the existing `tools.ci_review run` wrapper. The local interpreter version differs from CI's Python 3.11 matrix; the results are not a claim about an unexecuted platform.

The installed-wheel run used the existing `tools.ci_review wheel-test` policy, which excludes four source/build inspection modules and imports the installed distribution from outside the checkout. Its additional skips are explicit source-only fixtures/scripts and absent optional cryptography/jsonschema dependencies, in addition to native Windows cases. The full source environment did exercise the installed cryptography backend. These two suite totals describe different environments and must not be summed as distinct coverage.

Separate static review covered managed transaction recovery, temporal/current filtering, candidate handling, product status and composed entrypoints. Findings were fixed before the final test run. This review is not human operator signoff or independent source authentication.

## Remaining acceptance boundaries

This package does not connect clients, start a persistent service, change schedules/startup, activate an operational queue, merge/deploy, publish a package or mutate the owner's real memory. It does not grant execution, capital or trading permission.

For Person Twin, H3 C0 and native T11/T12 evidence, the Portable Twin Vault composition, authenticated owner/consent/egress bindings, durable disclosure/replay custody and exact human signoff remain distinct acceptance work. See the twelve-family matrix for what is already implemented and what evidence was not present in the reviewed set. A passing test suite or closed GitHub issue does not supply those receipts.
