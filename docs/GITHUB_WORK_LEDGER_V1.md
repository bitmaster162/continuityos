# GitHub Work Ledger v1

R11.1 proves that one coding run starts from an exact task, session capsule, Git
baseline, candidate branch, path scope, validation plan and effect ceiling.  The
Work Ledger preserves the rest of that run as an immutable, content-addressed
JSONL chain.

```text
WORK_ADMISSION_PASS
        ↓
WORK_DELTA_PASS
        ↓
WORK_TRANSPORT_PASS
        ↓
GPT semantic decision
        ↓
WORK_CLOSED or WORK_REJECTED
```

The ledger is a durable record, not an executor. It does not create branches,
push, merge, create PRs, deploy, apply registry/current state/R63, access wallets
or orders, trade, or record Robert's irreversible approval.

## Design

Each line is one canonical JSON event. Every event contains:

- a deterministic `ledger_id` derived from the exact admission identity;
- a monotonic sequence number;
- the previous event SHA-256;
- an event-specific receipt binding;
- an exact actor role;
- the unchanged `R63` authority and DENY effect ceiling;
- its own SHA-256 over canonical bytes.

The input ledger is never edited. Every extension creates a new successor file,
so previous states remain byte-addressable and rollback is simply choosing the
prior file.

## Initialize from admission

```bash
continuity work-ledger init \
  --admission-receipt WORK_ADMISSION_RECEIPT.json \
  --out work-00-admitted.jsonl
```

Requirements:

- schema `continuityos.work_admission.receipt/v1`;
- `WORK_ADMISSION_PASS` / `WOULD_ALLOW`;
- exact task/body, admission binding, repository and candidate branch;
- R63;
- no live-state or dangerous effect.

## Append verified delta

```bash
continuity work-ledger append-delta \
  --ledger work-00-admitted.jsonl \
  --delta-receipt WORK_DELTA_RECEIPT.json \
  --out work-01-delta.jsonl
```

The delta must be `WORK_DELTA_PASS`, match the admission receipt and binding,
carry the exact candidate HEAD/tree and exact validation receipt SHA, and contain
at least one changed path.

## Append GitHub transport

```bash
continuity work-ledger append-transport \
  --ledger work-01-delta.jsonl \
  --transport-receipt WORK_TRANSPORT_RECEIPT.json \
  --out work-02-transport.jsonl
```

The transport receipt must:

- use schema `continuityos.work_transport.receipt/v1`;
- preserve repository identity and visibility;
- bind the exact delta receipt SHA;
- prove remote HEAD/tree equal the verified candidate;
- prove GitHub Actions `success` on that HEAD, or explicitly state
  `NOT_CONFIGURED` without inventing a run;
- record a bounded `HOST_EXECUTOR`;
- deny force-push, merge, deployment, registry/current-state/R63 apply, wallet,
  order, external-message, self-application and trading effects.

## Append GPT semantic review

```bash
continuity work-ledger append-semantic \
  --ledger work-02-transport.jsonl \
  --semantic-decision WORK_SEMANTIC_DECISION.json \
  --out work-03-reviewed.jsonl
```

Only reviewer `{ "role": "GPT_CONTROLLER", "id": "GPT" }` is accepted.
Fable, Antigravity, Codex, Spark and other executors cannot self-accept their own
work.

Allowed verdicts:

- `ACCEPT`
- `PASS_WITH_CONDITIONS`
- `HOLD`
- `REVISE`
- `REJECT`

`ACCEPT` has no conditions. Every other verdict requires at least one condition
or reason. Every decision remains `content_status=REVIEWED` and
`apply_status=NOT_APPLIED`.

A `HOLD` ledger may receive a later, different GPT decision bound to the same
candidate and transport. Replaying the same decision bytes is rejected.

## Finalize

```bash
continuity work-ledger finalize \
  --ledger work-03-reviewed.jsonl \
  --out work-04-terminal.jsonl
```

- `ACCEPT` or `PASS_WITH_CONDITIONS` → `WORK_CLOSED`
- `REVISE` or `REJECT` → `WORK_REJECTED`
- `HOLD` → no output; the command returns `WORK_LEDGER_HOLD`

`WORK_CLOSED` means the candidate work lifecycle is complete and may be handed
to a separate integration/merge decision. It does **not** merge or apply
anything.

## Verify and project

```bash
continuity work-ledger verify --ledger work-04-terminal.jsonl
continuity work-ledger project --ledger work-04-terminal.jsonl
```

Verification rejects:

- non-canonical JSONL, BOM or missing final newline;
- sequence, timestamp, previous-hash or event-hash drift;
- changed ledger identity;
- duplicate receipt replay;
- illegal event order;
- terminal extension;
- non-R63 authority;
- force-push, merge, deployment, state apply, wallet/order/trading or
  self-application widening;
- wrong actor role;
- candidate/remote/Actions mismatch;
- semantic decision not authored by GPT;
- semantic self-apply or candidate mismatch.

Projection emits the current state, exact receipt chain, candidate and remote
HEAD/tree, semantic verdict, conditions and whether the closed work is an
**integration candidate**. Integration itself remains a separate future gate.

## State machine

```text
ADMITTED
  └─ DELTA_VERIFIED
       └─ TRANSPORT_VERIFIED
            ├─ SEMANTIC_ACCEPTED ── WORK_CLOSED
            ├─ HELD ── SEMANTIC_REVIEWED again
            └─ SEMANTIC_REJECTED ── WORK_REJECTED
```

No event may be appended after `WORK_CLOSED` or `WORK_REJECTED`.
