# Sovereign Twin Local Runtime R1

Status: **product/runtime engineering only**. This is not R13 scientific evidence and does not authorize Case #001 execution or any external action.

## Goal

Run a personal local Twin continuously against ContinuityOS memory while keeping the model replaceable.

```text
ContinuityOS Memory (read-only)
        |
        v
deterministic recall/evidence refs
        |
        v
SovereignTwinRuntime
        |
        v
LM Studio / llmster on 127.0.0.1:1234
        |
        +-- fast -> qwen3.5-4b
        `-- deep -> qwen3.6-35b-a3b
```

The runtime is local-only by default, injects evidence references (`mem:<id>`), distinguishes memory-backed context from model inference, and always returns `execution_authority=NONE`, `can_execute=false`.

## Commands

```bash
sovereign-twin --db ~/.continuityos/memory.db doctor
sovereign-twin --db ~/.continuityos/memory.db ask "What should I remember about this project?"
sovereign-twin --db ~/.continuityos/memory.db ask --mode deep "Review this difficult decision."
```

LM Studio / llmster is expected on `http://127.0.0.1:1234`.

## Current R1 boundaries

- no automatic memory write-back;
- no tool execution;
- no shell/file/message/order authority;
- no automatic FAST/DEEP routing yet;
- no background Windows service installer yet;
- no claim that R13 scientific qualification proves behavioral-twin accuracy;
- the local model remains replaceable; memory/evidence is outside model weights.

## Next engineering slice

1. Windows bootstrap + doctor script for `llmster`;
2. JIT/Auto-Evict profile validation;
3. optional explicit memory-admission queue (human review before write);
4. local UI/API shell;
5. dogfood and LIVE TwinBench evidence.
