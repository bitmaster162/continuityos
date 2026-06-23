# Architecture

## System Overview

```
                    ┌──────────────────────────┐
                    │      Owner / Operator      │
                    │   (Telegram, CLI, IDE)     │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │     Agent (Hermes, etc)    │
                    │   LLM + Tools + Skills     │
                    └─────┬────────────┬────────┘
                          │            │
                    MCP ──┘            └── CLI / HTTP API
                          │            │
                    ┌─────▼────────────▼────────┐
                    │      ContinuityOS Core      │
                    │                             │
                    │  ┌─────────┐  ┌──────────┐ │
                    │  │ Memory   │  │ Continuity│ │
                    │  │ (SQLite) │  │ (Checkpts)│ │
                    │  │ FTS5+Vec │  │  HashChain│ │
                    │  └────┬────┘  └────┬─────┘ │
                    │       │            │        │
                    │  ┌────▼────┐  ┌───▼──────┐ │
                    │  │  Twin   │  │   Gate    │ │
                    │  │(Predict)│  │(Preflight)│ │
                    │  └─────────┘  └──────────┘ │
                    │       │                    │
                    │  ┌────▼────┐               │
                    │  │ Control │               │
                    │  │  Plane  │               │
                    │  │(Frontier)│              │
                    │  └─────────┘               │
                    └────────────────────────────┘
```

## Components

### Memory (`memory.py`, `store.py`, `embed.py`)
- **Storage**: SQLite, single file, WAL mode
- **Keyword search**: FTS5 (BM25 ranking)
- **Semantic search**: Vector embeddings (cosine similarity)
- **Default embedder**: HashingEmbedder (zero deps, char n-grams)
- **Production embedder**: FastEmbed bge-small-en-v1.5 (384-dim, ONNX)
- **Hybrid scoring**: `0.5 * semantic + 0.5 * keyword_normalized`

### Continuity (`continuity.py`)
- **Checkpoints**: Session-level state snapshots
- **Hash-chain**: Each checkpoint links to previous (SHA-256)
- **Handoff**: Serializes state for agent transfer
- **Compress**: Consolidates old checkpoints

### Gate (`gate/`)
- **Classifier** (`classifier.py`): Severity classification (critical/high/medium/low)
- **Policy** (`policy.py`): Rule-based decisions (DENY/REQUIRE_CONFIRMATION/ALLOW)
- **Engine** (`engine.py`): Orchestrates classification + policy
- **Ledger** (`ledger.py`): Hash-chain audit trail
- **Rollback** (`rollback.py`): Undo plans for destructive actions

### Twin (`twin.py`)
- **predict()**: Digital twin — predicts owner's stance using memory + rules
- **alignment()**: Checks proposed action against canon/rules

### Control Plane (`control.py`)
- **Frontiers**: trunk (active focus), cash (revenue), lab (experiments)
- **Doctor**: Health checks (identity, purpose, invariants)

### MCP Server (`mcp_server.py`)
- **Protocol**: JSON-RPC over stdio (MCP 2024-11-05)
- **Tools**: 12 exposed functions
- **Transport**: Launches as subprocess, communicates via stdin/stdout

### CLI (`cli.py`)
- **Entry points**: `cos` (memory/continuity), `continuity` (gate)
- **Subcommands**: remember, recall, predict, alignment, checkpoint, doctor, etc.

### HTTP API (`api.py`)
- **Endpoints**: POST /remember, GET /recall, GET /namespaces
- **Zero deps**: Uses stdlib `http.server`

## Data Flow

1. **Agent receives user request** → checks memory via `recall`
2. **Before destructive action** → calls `preflight_action` (gate)
3. **Gate returns** ALLOW / DENY / REQUIRE_CONFIRMATION
4. **Agent executes** → records outcome via `checkpoint`
5. **Daily** → `doctor` cron verifies health, `backup` cron saves DB

## File Layout

```
continuityos/
├── continuityos/           # Python package
│   ├── memory.py           # Memory API
│   ├── store.py            # SQLite + FTS5 + vectors
│   ├── embed.py            # HashingEmbedder (default)
│   ├── embedders.py        # FastEmbed / SentenceTransformer
│   ├── continuity.py       # Checkpoints + hash-chain
│   ├── twin.py             # Digital twin
│   ├── control.py          # Frontiers + doctor
│   ├── agents.py           # Council of agents
│   ├── mcp_server.py       # MCP server (12 tools)
│   ├── api.py              # HTTP API
│   ├── cli.py              # CLI entry point
│   └── gate/               # Governance gate
│       ├── engine.py
│       ├── classifier.py
│       ├── policy.py
│       ├── ledger.py
│       └── rollback.py
├── tests/                  # 18 tests (gate, memory, hook)
├── examples/               # Demo scripts
├── docs/                   # Documentation
├── Dockerfile              # Container image
├── docker-compose.yml      # Production compose
└── pyproject.toml          # Package config
```
