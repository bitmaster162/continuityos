# Sovereign Twin Local Runtime R2

Status: product/runtime engineering only. This is not SCT R13 scientific evidence.

## Runtime topology

- LM Studio / llmster stays loopback-only at `127.0.0.1:1234`.
- Native LM Studio REST API v1 is used for model inventory and chat.
- FAST profile: `qwen3.5-4b`, context 8192, reasoning off.
- DEEP profile: `qwen3.6-35b-a3b`, context 4096, reasoning on.
- DEEP is unloaded immediately after a completed answer on the constrained 16 GB laptop profile.
- ContinuityOS memory is opened read-only for grounding; answers cite `mem:<id>`.
- No tools, file mutation, orders, messages, or execution authority are exposed by the model runtime.

## LM Studio settings expected on the 16 GB / RTX 2060 profile

Per-model defaults should keep:
- GPU offload at maximum/automatic maximum feasible;
- Flash Attention on;
- KV cache on GPU;
- maximum concurrent predictions = 1;
- CPU thread pool = 6.

`sovereign-twin doctor` reads `/api/v1/models` and reports the visible/loaded model state.
When a model is already loaded it also checks context length, `parallel`, Flash Attention,
and KV-cache placement.

## CLI

```powershell
sovereign-twin doctor
sovereign-twin ask "What should I focus on?" --mode fast
sovereign-twin ask "Review this architecture" --mode deep
sovereign-twin serve --host 127.0.0.1 --port 8765
```

The UI/API shell is then at `http://127.0.0.1:8765/`.

Endpoints:
- `GET /health`
- `GET /doctor`
- `POST /ask`
- `GET /admissions`
- `POST /admissions`

The R2 HTTP server refuses non-loopback binds.

## Shadow memory admission

Potential memories are not silently written into canonical ContinuityOS memory.
They are appended to a separate hash-chained JSONL admission queue with
`status=PENDING` and `canonical_memory_mutated=false`.

CLI:

```powershell
sovereign-twin admission-propose "Candidate preference" --namespace rules --tag candidate
sovereign-twin admission-list
```

Human-reviewed admission into canonical memory is deliberately a later step.

## Windows llmster

Repository scripts:
- `scripts/windows/SovereignTwin-LLMStudio-Setup.ps1`
- `scripts/windows/SovereignTwin-Status.ps1`

The setup script:
1. refuses to kill the LM Studio GUI automatically;
2. installs/updates llmster via the official LM Studio Windows installer;
3. starts `lms daemon up`;
4. starts the server explicitly on `127.0.0.1:1234`;
5. verifies `/api/v1/models`;
6. creates a per-user Scheduled Task to start llmster + server at logon.

The Windows Scheduled Task wrapper is ContinuityOS product glue, not an LM Studio-provided recipe.

## Scientific boundary

This runtime does not:
- alter the immutable R13 50-call qualification;
- open, predict, reveal, or score Case #001;
- change the frozen scientific Qwen substrate;
- grant merge/deploy/trading/execution authority.

`can_execute=false`; `execution_authority=NONE`.
