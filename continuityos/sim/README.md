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

## Epistemic safety (the point)

The agent can experiment and fail all it wants — **canon never gets poisoned**. On a
plateau or a constraint breach, garbage stays in `experiment_history`; the verified
truth is protected and, if needed, restored. Proven in the module self-tests.

## Status

Etaps 4–7 done (gateway, memory, detector, rollback) on the mock engine — MVP works
end-to-end. Etaps 8 (gRPC to real Pandora) and 9 (prod stack: Temporal / OPA-Rego /
XTDB / Ray / OTel) are the remaining infrastructure steps.

Each module has a runnable `__main__` self-test: `python -m continuityos.sim.gateway`, etc.
