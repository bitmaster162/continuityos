# MCP offline-first embedder selection — R1

Specification status: RC. Scope: the existing stdio MCP server, not a replacement
runtime, permission issuer, model router, schema migration, or OS sandbox.
Predecessor: `34d02e44104146beba7b174a88d58270606891fd` (A4/A3, PR #214).
Implementation and test qualification belong to the exact local commit and its
separate evidence manifest; this document is not production admission.

## Why this change

The predecessor constructed `FastEmbedEmbedder()` on every `Server` startup and
fell back to `Memory(db)` after any exception in that block. This included calls
with `CONTINUITYOS_EMBEDDER=hash` or `offline`. Core `cos` already requires explicit
opt-in for optional model construction. A synthetic constructor sentinel and
actual stdio child processes reproduce the difference without a real model.

## Selection contract

The server samples `CONTINUITYOS_EMBEDDER` once on construction, strips surrounding
whitespace, and lowercases it. It does not cache the setting process-wide or
change the embedder of an already-created server.

| Environment value | Behavior |
| --- | --- |
| Unset, empty, whitespace only | `Memory` uses its local `HashingEmbedder` default |
| `hash`, `hashing`, `offline`, `local` (case-insensitive) | Same local default; no optional constructor |
| `fast`, `fastembed` (case-insensitive) | Explicit opt-in: attempt the existing optional constructor |
| Any other value | Raise `ValueError("UNSUPPORTED_EMBEDDER_MODE")` before DB resolution/opening |

Offline modes do not import `continuityos.embedders` on this startup branch or
instantiate FastEmbed. Other application code may independently import modules;
this is not a blanket import prohibition.

For explicit fast opt-in only, constructor/import failure retains the prior
fallback to the local default. This does **not** prove that an existing vector
index is compatible with a different embedder, and is not a migration mechanism.
An operator relying on FastEmbed must explicitly select it and separately verify
backend availability and the matching existing embedding space.

`Memory` is constructed exactly once after selection. An exception from Memory
initialization is propagated; it must not trigger reopening the same database
with another embedder. Constructor-failure fallback is not permission to bypass
Memory, store, path, or effect guards.

## CURRENT and authority boundaries

The existing direct-surface wrapper remains outside `Server.__init__`. A declared
CURRENT binding must still pass the existing boundary before startup. Invalid or
incomplete declarations cannot become a legacy fallback. Module execution via
`python -m continuityos.mcp_server` remains subject to its existing guard.

No CURRENT checker, effect ceiling, R14 witness, R15 runtime binding, policy
snapshot, database resolver, broker registry, transaction, execution path, or
JSON-RPC tool schema is changed. Unknown embedder mode is validated before DB
resolution; the previously loaded policy is never swapped to make a test pass.

`fast` is a choice of optional loader, not authorization for a forbidden current
session, real personal-memory disclosure, trading, network access, or production.
The broader mandatory-path/OS-isolation gate remains unqualified.

## Verification

`tests/test_product_mcp_offline.py` covers:

- Default/offline aliases with a constructor sentinel; fast aliases with a
  recording fake backend; constructor-failure fallback.
- Invalid mode before resolver, Memory, loader, or database effect; existing
  synthetic database preservation on rejection.
- One Memory construction even when it fails; separate instances independently
  sample mode; exact existing DB and one policy snapshot reach the broker.
- Declared-current rejection for direct construction and `main`, including
  unknown mode and fast opt-in.
- Actual stdio process startup, remembering a synthetic marker, and rejection
  before protocol/DB initialization; a local fake `fastembed` module makes both
  optional import and construction observable without downloading a model.

The same new test bodies are run against the unchanged predecessor first and
then against the patch. Existing broker/MCP tests and current-boundary/Person
regressions remain unmodified. Optional-available qualification uses a synthetic
sentinel package, not a live ONNX model. Optional-absent qualification uses a
minimal disposable Python environment with no shared site-packages or pip fetch.
A test-local Python audit denies socket creation, DNS and connections, allowing
only local hostname lookup for JUnit metadata. It is not OS-level isolation.

## Compatibility and limits

The default choice changes on hosts with FastEmbed installed: installing an
optional dependency alone no longer activates it in MCP. Existing FastEmbed users
must set `CONTINUITYOS_EMBEDDER=fast` or `fastembed`. No records are re-embedded,
no vector metadata is silently rewritten, and no active installation is switched
by publishing or testing this source change.

The plain Python API raises on unknown mode. The unbound stdio entry point exits
nonzero before serving JSON-RPC; it does not emit a successful initialization or
silently substitute hash/fast. Existing bound-session errors retain precedence.

No live-model/download, real-data, cross-machine, packaged-release, or independent
Opus qualification is claimed by the local sentinel tests. No push, PR change,
merge, deployment, scheduler, service, TPM, OS account, or ACL operation is part
of this local work order. `C0 HOLD`; `NOT_PRODUCTION_ADMITTED`.
