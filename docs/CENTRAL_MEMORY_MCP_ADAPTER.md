# CENTRAL MEMORY MCP adapter (draft)

## Boundary
Separate allowlisted MCP entrypoint over the existing ContinuityOS core. It does not modify mcp_server.py, CORE, RUAP, the canonical memory database, or any client configuration.

Exactly six tools are exposed: registry_read, memory_recall, memory_find, memory_namespaces, journal_append, gate_request. The adapter does not expose or forward forget, memory writes, execute_preflight, or arbitrary core tool names. Gate requests call preflight_exec only.

## AI-selection registry contract
The registry is a separate bounded projection prepared by the “План CENTRAL MEMORY R2” chat, not a replacement for canonical CENTRAL MEMORY R1/R2 payload. UTF-8 JSON path is CONTINUITYOS_AI_SELECTION_PATH (default ~/.continuityos/ai_selection_registry.json):

    {
      "schema": "continuityos.ai_selection_registry/v1",
      "records": [{
        "line": "CENTRAL_MEMORY",
        "executor_chat": "План CENTRAL MEMORY R2",
        "bucket": "active",
        "current_state": "HOLD",
        "next_turn": "adapter integration",
        "evidence": "source receipt or pointer",
        "updated_at": "2026-10-29T00:00:00Z"
      }]
    }

Fields preserve the selection contract: линия, исполнитель и чат, корзина, сейчас, чей ход, доказательство, обновлено. Returned output includes source SHA-256 and canonical_truth_promoted=false. The adapter does not invent records or promote a file to authority.

This stays separate from CENTRAL_MEMORY_R2_PLAN_20261017 payload v2: historical decisions and projects remain immutable; assessments/effective overlays and unresolved/supersession records stay separate; source manifests and validation receipts remain authoritative. The adapter does not mutate or promote these sources.

## Journal and gate
Journal path is CONTINUITYOS_ADAPTER_JOURNAL (default ~/.continuityos/ai_selection_journal.jsonl). Entries are JSONL, appended, flushed and fsynced. This API does not claim OS-level tamper-proof storage.

gate_request submits exact request_id, argv, cwd and optional paths for GateBroker preflight only. It never calls execute_preflight.

## Verification
Run pytest -q tests/test_central_memory_mcp_adapter.py. No clients are connected by this PR. No merge or deployment is authorized.
