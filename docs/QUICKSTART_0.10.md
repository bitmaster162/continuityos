# ContinuityOS 0.10 Quick Start

ContinuityOS 0.10 is organized around one product goal: carry durable project context across AI sessions and MCP-capable clients without rebuilding that context by hand.

## 1. Install

```bash
pip install continuityos
cos --version
```

Expected version for this release candidate:

```text
continuityos 0.10.0
```

## 2. Initialize local continuity

```bash
cos setup
```

For a non-interactive local bootstrap:

```bash
cos setup --quick
```

## 3. Import existing AI history

ContinuityOS auto-detects supported ChatGPT, Claude, Gemini, Grok, Mistral and Perplexity exports.

```bash
cos import <export-path> --dry-run
cos import <export-path> --extract
```

`--dry-run` previews without writing. `--extract` stores distilled typed memories instead of blindly treating every raw turn as a durable fact.

## 4. Inspect client connection state

```bash
cos connect --status
```

Managed clients in v0.10:

- Claude
- Cursor

Guidance-only clients:

- Hermes
- generic MCP

## 5. Connect one MCP client

Always preview first:

```bash
cos connect claude --dry-run
```

Then explicitly confirm the write:

```bash
cos connect claude --yes
```

For Cursor:

```bash
cos connect cursor --dry-run
cos connect cursor --yes
```

Managed connection preserves unrelated config keys, records rollback state, detects drift, verifies MCP initialization, and rolls back automatically if post-write verification fails.

## 6. Check product health

```bash
cos status
```

Machine-readable form:

```bash
cos status --json
```

`cos status` is read-only. If the SQLite database is not quiescent, it fails closed instead of presenting a potentially stale snapshot.

## 7. Prove continuity independently

```bash
cos demo continuity
```

Machine-readable form:

```bash
cos demo continuity --json
```

The demo creates an isolated temporary database, writes a known continuity state, closes the writer, starts a separate Python process, reopens the state read-only, verifies recovery, and removes the temporary directory.

It does not resolve, read or write the normal user memory database and does not require an external model or network service.

## 8. Resume normal work

```bash
cos boot
```

The daily loop is:

```text
work
-> remember / checkpoint
-> close session
-> open another session or client
-> boot / MCP context
-> continue
```

Useful continuity commands:

```bash
cos checkpoint --summary "what changed" --next "next action" --proof <artifact>
cos doctor
cos handoff
cos boot
```

## 9. Discover commands

```bash
cos --help
```

The v0.10 help surface leads with:

```text
setup
import
connect
status
demo continuity
boot
```

Advanced governance and operator commands remain available, but they are not required for the basic product flow.
