# Sim-OS — closed-loop self-improving simulation bridge

Sim-OS is the ContinuityOS ↔ **Pandora** bridge: a durable OODA loop that lets an agent
propose hypotheses, run them in an isolated simulation engine, and crystallize only
*verified* results into canon — safely, with rollback. It's the research/experimentation
layer that sits on top of the ContinuityOS memory + governance core.

```
python -m continuityos.sim.loop --objective edge --iters 6
# or
cos sim --objective edge --iters 6
```

## The loop (§ refs = architecture spec)

```
intent → Governance Gateway → SimulationSpec → Pandora → bitemporal memory
           (ALLOW/WARN/HOLD/DENY, §2)           (mock)     (canon vs experiment, §3.3)
                                                             │
                          rollback ← hallucination detector ←┘
                          (§4.2)      (semantic stall + plateau, §4.1)
```

| Module | Role |
|---|---|
| `contracts.py` | `SimulationSpec` / `SimulationResult` — the versioned, content-addressed data contract (Merkle-DAG provenance). |
| `gateway.py` | Deterministic risk-scoring gate → ALLOW / WARN / HOLD / DENY. Canon breach = instant DENY. |
| `pandora_mock.py` | Stateless sim engine stub. Swap for a gRPC client to the real Pandora. |
| `memory_plane.py` | Bitemporal split: verified **canon** (supersede-on-confident) vs branching **experiment history**. Backed by `continuityos.memory`. |
| `detector.py` | Hallucination-loop detector: frozen params + flat metric + repetition → stop. |
| `rollback.py` | Autonomous rollback to the last verified canon on any failure mode. |
| `loop.py` | Wires it all into the OODA loop. |

## Epistemic safety (the design goal — with honest guarantees)

The intent: an agent experiments freely, but verified truth (canon) is protected. What
the code actually enforces today (hardened after an external audit, 2026-07-04):

- **Promotion requires replication, not one lucky run.** A result only enters canon after
  `min_confirmations` runs clear a `verify_threshold` set *above* the loop's success bar.
  A single passing iteration stays in `experiment_history`.
- **Rollback restores state, not just logs it.** On any failure mode the current-canon
  pointer is reset to the last verified row and the confirmation counter is zeroed, so
  poisoned progress can't auto-promote. Experiment history stays intact for audit.
- **Fail closed.** If the durable store can't be opened, the plane raises — it does **not**
  silently degrade to ephemeral RAM. Stub/in-memory mode is explicit opt-in (`allow_stub`).
- **Spec identity is a full content hash** over all material fields (objective, params,
  constraints, budget, stopping criteria, operator canon, provenance).

**Honest limits:** this runs on a *mock* Pandora, and "verified" here means replication
against that mock — not out-of-sample, independent-verifier, or human-threshold
verification, which belong to a real deployment. The gateway enforces whatever operator
canon is loaded; the demo loop injects placeholder bounds (see `build_spec`). Treat this
as a hardened scaffold, not a battle-tested safety certificate.

## Status

Etaps 4–7 implemented (gateway, memory, detector, rollback) on the mock engine; core
invariants hardened per external audit. Etaps 8 (gRPC to real Pandora) and 9 (prod stack:
Temporal / OPA-Rego / XTDB / Ray / OTel) remain. Each module has a runnable self-test:
`python -m continuityos.sim.<module>`.

Each module has a runnable `__main__` self-test: `python -m continuityos.sim.gateway`, etc.
