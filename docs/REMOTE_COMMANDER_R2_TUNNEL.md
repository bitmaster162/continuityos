# ContinuityOS Remote Commander R2 — Secure MCP Tunnel

## Baseline

R2 is a dependent change based on R1 head
`84cf11c679f63db853cf3aa14996a811d01d1bc2`.
R1 itself is based on current `master`
`2c701b2463f62f8e43374a8f40cdb289d0bc1bad`.

R2 does not require ChatGPT Pro to build or validate locally.

## Purpose

R2 connects the private stdio Remote Commander MCP to OpenAI Secure MCP Tunnel
without exposing an inbound port.

Data path:

`ChatGPT/OpenAI -> OpenAI tunnel control plane <- outbound HTTPS tunnel-client -> local stdio ContinuityOS Remote MCP`

The tunnel is transport only. ContinuityOS remains the authority boundary.

Official implementation reference:
`https://github.com/openai/tunnel-client`.

## Pro read-only profile

When launched with:

`--tool-profile chatgpt-pro-readonly`

the server advertises and accepts only:

- `capability_status`
- `system_info`
- `fs_list`
- `fs_read`

The restriction is enforced twice:

1. `tools/list` omits every base memory/write/execution tool.
2. `tools/call` rejects hidden tool names even if a client attempts a direct call.

This means `remember`, `upsert`, `forget`, `preflight_exec`, and
`execute_preflight` are unavailable on this profile.

## Windows launcher

Use:

`scripts/windows/ContinuityOS-RemoteTunnel.ps1`

Safe pre-Pro validation:

```powershell
.\scripts\windows\ContinuityOS-RemoteTunnel.ps1 -Mode Plan -RemoteRoot C:\path\to\allowed\root
```

After OpenAI tunnel credentials exist, set them only in the current process
environment. Do not commit them or place them in the MCP command:

```powershell
$env:CONTROL_PLANE_API_KEY = "<runtime-key>"
$env:CONTROL_PLANE_TUNNEL_ID = "<tunnel-id>"

.\scripts\windows\ContinuityOS-RemoteTunnel.ps1 -Mode Init -RemoteRoot C:\path\to\allowed\root
.\scripts\windows\ContinuityOS-RemoteTunnel.ps1 -Mode Doctor
.\scripts\windows\ContinuityOS-RemoteTunnel.ps1 -Mode Run
```

The launcher passes no API key or bearer token on the command line. The official
`tunnel-client` inherits the runtime key from the environment.

`CONTROL_PLANE_TUNNEL_ID` must match `tunnel_` plus exactly 32 lowercase hex
characters. The runtime API key should be restricted to Tunnels Read + Use;

## Security invariants

- no inbound listener is created by ContinuityOS;
- no public MCP endpoint is required;
- no arbitrary `--mcp-command` input is accepted by the launcher;
- the MCP child command is fixed to `continuityos.remote_mcp_server`;
- the remote root must already exist;
- credential/key paths remain denied by R1;
- Pro tunnel surface is read-only at the server, not merely in the ChatGPT UI;
- R2 does not merge, deploy, trade, touch wallets, or grant capital authority.

## Qualification

R2 is code-complete only when:

1. R1 review-gates are green on its synchronized head;
2. R2 unit/static tests pass on Linux and Windows CI;
3. R2 CodeQL and P0 checks are green;
4. a later local Windows test proves `Plan` without credentials;
5. once tunnel credentials are available, `Init -> Doctor -> Run` is tested with
   the official OpenAI tunnel-client.

The last step is runtime qualification and cannot be claimed from CI alone.
