# ContinuityOS — Quickstart Guide

## 1. Install

```bash
# Clone
git clone <repo-url> continuityos
cd continuityos

# Create venv
python -m venv .venv
source .venv/Scripts/activate    # Windows (git-bash)
# source .venv/bin/activate       # Linux/macOS

# Install (core = stdlib only, zero ML deps)
pip install -e .

# Optional: real semantic embeddings (recommended)
pip install -e ".[fast]"          # fastembed: ONNX, ~90MB
```

## 2. Initialize Memory

```bash
cos --db memory.db boot
# → Creates SQLite DB with FTS5 + vector tables
```

## 3. Store & Recall

```bash
# Remember
cos --db memory.db remember "Project X uses PostgreSQL on port 5432" --namespace facts

# Recall (semantic + keyword hybrid)
cos --db memory.db recall "database config" -k 3
# → 0.79 [facts] Project X uses PostgreSQL on port 5432 ...
```

## 4. Checkpoints

```bash
# Close a session
cos --db memory.db checkpoint \
  --summary "Set up CI/CD, added predict/alignment to CLI" \
  --next "Push to GitHub, configure secrets"
```

## 5. Governance Gate

```bash
# Check action safety before executing
continuity preflight shell "rm -rf /tmp/test"
# → ⛔ DENY (critical): rm_rf

continuity preflight shell "ls -la /tmp"
# → ✓ ALLOW (low)
```

## 6. Digital Twin

```bash
# Predict owner's likely stance
cos --db memory.db predict "deploy to production on Friday"

# Check action against canon
cos --db memory.db alignment "delete all trading history"
```

## 7. MCP Integration (Hermes / Claude / Cursor)

Add to your MCP client config:

```yaml
mcp_servers:
  continuityos:
    command: python
    args:
      - /path/to/mcp_bridge.py
    enabled: true
```

12 tools become available: `remember`, `recall`, `context`, `forget`,
`list_namespaces`, `checkpoint`, `handoff`, `doctor`, `set_frontier`,
`predict`, `alignment`, `preflight_action`.

## 8. HTTP API

```bash
cos --db memory.db api --host 0.0.0.0 --port 8077
# → POST /remember {"text":"hello","namespace":"notes"}
# → GET /recall?q=hello&k=5
# → GET /namespaces
```

## 9. Docker

```bash
docker-compose up -d
# → API on http://localhost:8077
# → Persistent volume at /data/memory.db
```

## 10. Health Check

```bash
cos --db memory.db doctor
# → 8/8 healthy ✓
```
