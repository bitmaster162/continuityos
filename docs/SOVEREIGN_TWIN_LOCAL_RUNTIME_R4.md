# Sovereign Twin Local Runtime R4

R4 turns the CI-reviewed local runtime into a repeatable Windows dogfood install without changing the R13 scientific protocol or granting execution authority.

## Install flow

1. Finish `SovereignTwin-LLMStudio-Setup.ps1` and verify standalone llmster on `127.0.0.1:1234`.
2. Choose one exact CI-reviewed Git commit SHA.
3. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\SovereignTwin-Install-Runtime.ps1 -SourceSha <EXACT_40_HEX_SHA>
```

The installer:
- refuses to continue unless the llmster scheduled task and loopback API are present;
- downloads exactly the requested Git SHA from `bitmaster162/continuityos`;
- creates an isolated venv under `%LOCALAPPDATA%\SovereignTwin\runtime-venv`;
- installs ContinuityOS/Sovereign Twin with `--no-deps`;
- initializes `~/.continuityos/memory.db` only if needed;
- writes a source manifest binding the installed runtime to the exact Git SHA;
- creates a per-user `SovereignTwin-UI` scheduled task;
- starts the local UI/API only on `127.0.0.1:8765` and verifies `/health`.

Status:

```powershell
.\SovereignTwin-Runtime-Status.ps1
```

Open UI:

```powershell
.\SovereignTwin-Open.ps1
```

## Runtime topology

```text
Windows logon
  -> SovereignTwin-LLMStudio task
     -> standalone llmster
     -> LM Studio REST v1 on 127.0.0.1:1234
  -> SovereignTwin-UI task
     -> isolated Python venv
     -> Sovereign Twin API/UI on 127.0.0.1:8765
     -> read-only canonical ContinuityOS memory
     -> shadow admission queue for candidate memories
     -> FAST qwen3.5-4b / DEEP qwen3.6-35b-a3b via JIT
```

## Authority boundary

R4 remains local shadow/product engineering only:
- `can_execute=false`
- `execution_authority=NONE`
- no file/tool/message/order execution by the Twin runtime
- no automatic canonical-memory writes from model output
- no R13 model calls
- no Case #001 open/predict/reveal/score
- no merge implied by testing or installation
