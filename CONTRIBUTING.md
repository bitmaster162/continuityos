# Contributing to ContinuityOS

Thanks for helping build durable memory for agents and humans.

- Core stays **stdlib-only** (zero required deps). Optional features go under `[project.optional-dependencies]`.
- Run tests: `pip install -e ".[dev]" && pytest -q`.
- Never commit personal data, real memory DBs, or `data/` / `takeout/` (see `.gitignore`).
- Embeddings are pluggable: pass any `str -> list[float]` callable to `Memory(embedder=...)`.
- Keep the MCP tool surface small and well-described — agents read those descriptions.

By contributing you agree your contributions are licensed under Apache-2.0.
