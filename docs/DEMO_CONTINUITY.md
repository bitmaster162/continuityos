# `cos demo continuity`

`cos demo continuity` is a self-contained proof of ContinuityOS's core product promise: durable state survives a real session/process boundary and can reconstruct the next work context.

## Run it

```bash
cos demo continuity
cos demo continuity --json
```

Expected human-readable shape:

```text
ContinuityOS continuity demo  PASS
Boundary      separate Python process
  PASS  fact_recovered
  PASS  canon_recovered
  PASS  trunk_recovered
  PASS  cash_recovered
  PASS  open_loop_recovered
  PASS  checkpoint_recovered
  PASS  next_action_recovered
  PASS  doctor_healthy
  PASS  handoff_reconstructed
Doctor        HEALTHY  8/8
User memory   UNTOUCHED
External AI   NOT USED
Cleanup       PASS
Result        durable state survived a fresh process and reconstructed the next work context
```

## What the demo proves

The parent process:

1. creates a new temporary directory and temporary ContinuityOS memory DB;
2. records a unique run marker as a keyed fact;
3. records canon;
4. records trunk and cash frontiers;
5. records one open loop;
6. records a checkpoint with summary, proof, and next action;
7. checkpoints the temporary SQLite WAL and closes the writer;
8. starts a separate Python process.

The child process receives only the path to the persisted temporary DB and the random run marker. It opens the DB read-only and independently verifies:

- the exact keyed fact;
- the exact canon item;
- both frontiers;
- the open loop;
- checkpoint summary and proof;
- the recorded next action;
- a healthy `Continuity.doctor()` result;
- reconstruction of a handoff containing the recovered state.

Only when every recovery check passes does the parent emit `COS_DEMO_CONTINUITY_PASS`.

## Isolation guarantees

The demo deliberately does **not** use the user's normal ContinuityOS DB.

- `CONTINUITYOS_DB` is ignored by the proof flow.
- `cos --db ... demo continuity` is rejected with `USER_DB_ARGUMENT_NOT_ALLOWED` before temporary state is created.
- no client configuration is modified;
- no network request is made;
- no external model or AI API is called;
- no server is started;
- no deployment, dispatch, trading, wallet, or capital effect is allowed.

The demo does perform two bounded local effects by design: it writes an ephemeral demo DB and launches one local Python child process. The temporary directory is removed before the command reports PASS. Cleanup failure changes the terminal to HOLD.

## Why a separate process matters

Reopening the same database through a new object in the same interpreter is useful, but it could still leave room for accidental in-memory coupling. `cos demo continuity` crosses an operating-system process boundary, so the child cannot reuse the parent's `Memory`, `Continuity`, caches, or Python objects. Its only continuity source is the durable DB.

## Current-session containment

`cos demo continuity` remains behind the existing current-session containment. In a verified R64 READ_ONLY session, the command returns the existing `CURRENT_ENTRYPOINT_HOLD` before `demo.py` is imported, before a temporary directory is created, and before a child process is launched.
