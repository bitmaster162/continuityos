# Sovereign Twin Memory R5

R5 makes Twin memory semantically consistent with the local LM Studio stack.

## Embedding contract

Default embedding model:

```text
text-embedding-nomic-embed-text-v1.5
```

The Twin runtime uses LM Studio's loopback OpenAI-compatible `/v1/embeddings` endpoint for query embeddings. Seed/history commits use the same model for stored vectors.

Before any explicit canonical-memory commit, the ingestion layer probes the selected embedding dimension and fails closed if the existing DB contains a different dimension or mixed dimensions.

A successful commit writes `~/.continuityos/twin-memory-manifest.json` with the selected embedding model and dimension.

## Safe defaults

`seed-import` and `ingest-history` are **dry-run by default**. Canonical memory changes require an explicit `--commit` flag.

Model-generated memories do not use these commands automatically. They remain proposals in the separate shadow admission queue.

## Seed path

Validate only:

```bash
sovereign-twin seed-import examples/sovereign_twin_seed.example.json
```

Explicit commit:

```bash
sovereign-twin seed-import examples/sovereign_twin_seed.example.json --commit
```

Seed schema:

```json
{
  "schema": "sovereign-twin.memory-seed/v1",
  "entries": [
    {
      "text": "...",
      "namespace": "rules",
      "tags": ["..."],
      "type": "preference",
      "key": "stable.semantic.key"
    }
  ]
}
```

Entries with `key` use the existing append-only/superseding `Memory.upsert` path. Entries without a key append normally.

## Existing AI-history path

Dry run:

```bash
sovereign-twin ingest-history C:\path\to\export --source auto
```

Explicit commit:

```bash
sovereign-twin ingest-history C:\path\to\export --source auto --commit
```

The existing ContinuityOS adapters remain authoritative for ChatGPT, Claude, Gemini, Grok, Mistral, and Perplexity formats. Default imported roles remain the user's own turns (`user,human,memory`). `--extract` selects the existing distillation mode.

## Memory doctor

```bash
sovereign-twin memory-doctor
```

Returns local DB count, namespace counts and the set of stored vector dimensions without invoking an LLM.

## Authority boundary

- local loopback model server by default;
- canonical memory writes only by explicit user command with `--commit`;
- model-generated candidate memory remains shadow-only;
- `can_execute=false`;
- `execution_authority=NONE`;
- no R13 scientific calls;
- no Case #001 open/predict/reveal/score.
