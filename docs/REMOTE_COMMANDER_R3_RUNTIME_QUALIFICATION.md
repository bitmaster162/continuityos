# ContinuityOS Remote Commander R3 — Windows Runtime Qualification

## Baseline

R3 starts from merged `master`:

`5a72da36f104421010718da96681c3304fc48fe1`

Qualification was performed from a separate clean Windows checkout so the parallel R24 / PR #199 worktree and branch were not modified.

## Official tunnel-client artifact

Validated release:

- repository: `openai/tunnel-client`
- release: `v0.0.14`
- asset: `tunnel-client-v0.0.14-windows-amd64.zip`
- expected SHA-256: `784ab8da7b5a88f0109f1fd8aaf0a1c86067430b896dddf307ef7e3cc49fa1a5`
- observed SHA-256: exact match
- binary version: `0.0.14+0f870e50a973fa820d4c409000059e181e8d242b`

The official binary advertises `sample_mcp_stdio_local` and the MCP command profile contract used by ContinuityOS R2.

## Credential-free Windows result

The merged launcher `scripts/windows/ContinuityOS-RemoteTunnel.ps1` produced:

- schema: `continuityos.remote_tunnel_plan/v1`
- MCP transport: `stdio`
- MCP tool profile: `chatgpt-pro-readonly`
- public MCP listener: `false`
- health/UI listener: `127.0.0.1:8080`
- health/UI scope: `loopback`
- direct shell: `false`
- control-plane key present: `false`

The real Windows stdio MCP process was then exercised over JSON-RPC. It advertised exactly:

- `capability_status`
- `system_info`
- `fs_list`
- `fs_read`

A bounded `fs_read` of a benign repository file succeeded. A direct call to hidden write tool `remember` was rejected by the server-side profile boundary.

Observed local state on R3 head `8987f3f5feef5770493493ddf69615121837c767`:

`LOCAL_READONLY_RUNTIME_GREEN`

Related Windows regression set: `21 passed`.

## Fail-closed credential gate

With `CONTROL_PLANE_API_KEY` and `CONTROL_PLANE_TUNNEL_ID` absent:

- launcher `Doctor` exited non-zero and identified the missing runtime API key;
- launcher `Init` exited non-zero before creating a tunnel profile;
- no secret-like value was printed.

This is intentional. R3 does not manufacture, recover, persist, or log OpenAI runtime credentials.

## Reproducible harness

Run:

```powershell
.\scripts\windows\Test-ContinuityOS-RemoteRuntime.ps1 \
  -ExpectedHead <exact-commit-sha> \
  -TunnelClient C:\path\to\tunnel-client.exe
```

The harness fails closed unless the Git worktree is clean, the expected head matches when provided, the launcher plan preserves the read-only boundary, the official tunnel-client stdio sample is available, the MCP advertises exactly four read-only tools, a benign read succeeds, and a hidden write call is rejected.

## Remaining live qualification

The following is **not yet claimed**:

`Init -> Doctor -> Run -> ChatGPT connector discovery -> tools/list -> benign read through the live OpenAI tunnel`

That step requires operator-provided:

- `CONTROL_PLANE_API_KEY` with Tunnels Read + Use;
- `CONTROL_PLANE_TUNNEL_ID` for the intended OpenAI workspace.

Until those values exist at runtime, `live_tunnel_qualified=false`.

## Parallel branch isolation

At the time R23 was merged, R24 / PR #199 changed only replay/tamper-protection files and had no file overlap with R23 Remote Commander. R3 continues on its own branch and does not rebase, force-push, merge, or otherwise modify PR #199.
