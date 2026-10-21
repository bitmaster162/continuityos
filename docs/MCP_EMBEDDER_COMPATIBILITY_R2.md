# MCP embedding compatibility R2

Status: local corrective candidate; no activation or production admission.
Base: `1c9f8af5c2ecab74600f1171826fea2dc52397e6`, the reviewed PR #215 head.
This document supersedes only the R1 loader-failure fallback and startup
compatibility behavior. `MCP_OFFLINE_EMBEDDER_R1.md` remains the historical R1
contract; it has not been silently rewritten.

## Findings and scope

The owner-delivered Claude/Opus review identified two activation blockers.
Synthetic execution reproduced both: the R1 MCP default against a 384-D store
admitted a new 256-D row; a subsequent 384-D backend still failed when recall
included both dimensions. Explicit fast constructor failure could silently select
Hashing, even in an empty database. One-row sampling can miss existing mixtures.

This correction covers startup on the existing MCP path. It is not a Store write
guard, an embedder identity registry, a new runtime, or a database migration.

## Selection and failure contract

Mode normalization and the R1 aliases are unchanged. Default, empty, whitespace,
hash/hashing/offline/local do not import or construct FastEmbed. Only explicit
fast/fastembed selects the optional loader. Unknown modes raise
`UNSUPPORTED_EMBEDDER_MODE` before DB resolution. CURRENT containment retains
precedence; its implementation is unchanged.

**Intentional R1 contract change:** an explicitly selected FastEmbed import or
constructor failure raises `FAST_EMBEDDER_UNAVAILABLE`. No Hashing fallback,
warning-only degradation, or second Memory-open attempt is performed. The chained
exception retains the original failure. Path resolution may already have happened,
but Memory is not constructed on this failure path.

## Dimension barrier

After the single Memory construction, and before Continuity/Twin/control-plane
initialization or any JSON-RPC response, the server:

1. Calls the selected embedder once with the fixed synthetic probe
   `continuityos:mcp-embedding-dimension-probe:v1`. No stored record is supplied.
   Exceptions produce `EMBEDDER_PROBE_FAILED`; a non-list/tuple or empty result
   produces `EMBEDDER_PROBE_INVALID`.
2. Issues one SELECT for minimum/maximum vector byte length and a malformed count
   across all non-NULL `items.vec`. No text, namespace, or BLOB payload is returned
   to Python. Equal valid float32 widths imply a uniform stored dimension.
   Empty and NULL-only stores impose no stored-dimension constraint.
3. Rejects non-BLOB, empty, or non-float32-aligned payloads with
   `EMBEDDER_VECTOR_DATA_INVALID`. Mixed or incompatible widths produce
   `EMBEDDER_DIMENSION_MISMATCH store=<dimension-or-range> selected=<dimension>`
   and an operator hint. No records are deleted or repaired.
4. Closes the opened Memory connection and propagates any failure in this new
   validation block. Query failures remain failures; they do not mean empty store.

The aggregate reads all vector metadata and returns one row. Its scan cost grows
with store size. A mixed range in the error is min/max, not an enumeration of every
intermediate size. Vector lengths are float32 BLOB bytes divided by four.

Memory retains its existing initialization behavior, including WAL/schema work
where applicable. This check is before serving and adding a memory item, not a
claim that constructing arbitrary legacy Memory has zero filesystem effects.
A newly created empty database can exist if the later probe fails. No new schema,
re-embedding, automatic migration or repair is introduced.

## Compatibility and activation

HashingEmbedder uses 256 dimensions; the current FastEmbed bge-small backend uses
384. A 384-D database started in default/hash mode now fails before the first MCP
write. Switching back to fast does not repair already mixed rows: that store also
fails startup until separately restored or rebuilt under an approved procedure.

Vector length alone must not be used to infer backend identity. Two 256-D models
can inhabit different coordinate spaces. The barrier checks dimensions and BLOB
shape, not model identity, numeric finiteness, quality, provenance or authority.
Explicit fast mode may initialize a real optional model and then run the probe;
qualification tests use synthetic backends with network denied, not real models.

## Limits and regression contract

This is a startup snapshot, not a cross-process lock or continuous write invariant.
A raw Memory/Store writer can insert incompatible data after startup. A backend
whose output shape changes later is not constrained by this initial probe.
Core cos selection, Memory/Store/index, R14/R15, Person R21H and A4/A3 are unchanged.
Shared mode selection and full embedder identity are separate proposals.

R2 explicitly replaces the two parameterized R1 loader-failure fallback cases
with fail-closed expectations. Other original test bodies are preserved; the stdio
utility gains an optional synthetic import-failure mode. New tests cover all-row
versus one-row checking, order/namespace independence, malformed BLOBs, probe/query
errors and connection closure, compatible stores, fast failure, and real stdio
refusal before initialize/remember responses.

The prior Opus REVISE supports the findings; it is not approval of this correction.
Independent review and a new official wheel/CI remain required. No push, PR edit,
merge, deployment, runtime switch, real-user-data access, model download or trading
is part of this local work.
