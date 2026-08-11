# Current Environment Export v1 (R33)

`continuity current-env` removes manual current-session environment wiring without mutating the running process.

It accepts one explicit current cold-start challenge, the controller-pinned challenge SHA-256, and one BOOT_ACK. The exact binding is verified before any shell text is rendered.

## PowerShell

```powershell
continuity current-env `
  --challenge C:\path\CURRENT_COLD_START_CHALLENGE.json `
  --challenge-sha256 <exact-sha256> `
  --ack C:\path\CURRENT_COLD_START_BOOT_ACK.json `
  --format powershell
```

On PASS the command prints copy/paste assignments for:

- `CONTINUITYOS_CURRENT_CHALLENGE`
- `CONTINUITYOS_CURRENT_CHALLENGE_SHA256`
- `CONTINUITYOS_CURRENT_ACK`
- `CONTINUITYOS_CURRENT_SESSION_REQUIRED=1`

PowerShell single quotes are escaped by doubling them. Newline, carriage-return, and NUL path values fail closed rather than being rendered into shell text.

## POSIX shell

Use `--format posix` for shell-quoted `export NAME=value` lines.

## JSON

`--format json` is the default and returns the verified environment map plus authority generation, challenge/ACK identities, READ_ONLY session ceiling, NO_FURTHER_AGENT_WORK authority ceiling, execution HOLD, and a no-effects receipt.

## Recovery semantics

`current-env` validates the explicit command arguments and does not depend on the ambient current-session variables. This is intentional: an operator can recover from an incomplete or stale ambient binding by producing a fresh verified block.

The command never calls the legacy dispatcher, never mutates `os.environ`, never writes files, never executes a subprocess, and never grants execution authority.

`can_trade=false`, `capital_permission=DENY`, and `deploy_permission=DENY` remain unchanged.
