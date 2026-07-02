"""Orchestrator (Ф1, ORCA-паттерн но сильнее): OODA over a DAG of steps across
heterogeneous agents, with memory context, checkpoints and anti-looping.

Design: HANDOFF/ORCHESTRATOR_DESIGN_20260702.md. Agents are plain callables
(prompt -> str), so Claude/Hermes/OpenClaw plug in as thin adapters. Every step
is checkpointed; a failed step never leaks downstream (dependents -> blocked).

    from continuityos.orchestrator import Orchestrator, Step
    orc = Orchestrator(memory, agents={"hermes": call_hermes, "claude": call_claude})
    report = orc.run([Step("s1","collect arena digest", assignee="hermes"),
                      Step("s2","synthesize report", depends_on=["s1"], assignee="claude")])
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

MAX_ATTEMPTS = 3  # anti-looping: then escalate to human


@dataclass
class Step:
    id: str
    goal: str
    depends_on: List[str] = field(default_factory=list)
    assignee: str = ""
    status: str = "pending"   # pending|running|done|failed|blocked
    result: str = ""
    attempts: int = 0


class Orchestrator:
    def __init__(self, memory, agents: Dict[str, Callable[[str], str]],
                 gate: Optional[Callable[[Step], bool]] = None,
                 on_checkpoint: Optional[Callable[[Step], None]] = None,
                 context_k: int = 4):
        self.m = memory
        self.agents = agents
        self.gate = gate                    # returns False -> step blocked (canon conflict)
        self.on_checkpoint = on_checkpoint  # e.g. cos checkpoint / ledger append
        self.context_k = context_k

    def _ready(self, s: Step, steps: Dict[str, Step]) -> bool:
        return s.status == "pending" and all(
            steps[d].status == "done" for d in s.depends_on if d in steps)

    def _blocked_by_failure(self, s: Step, steps: Dict[str, Step]) -> bool:
        return any(steps[d].status in ("failed", "blocked")
                   for d in s.depends_on if d in steps)

    def run(self, step_list: List[Step]) -> Dict:
        steps = {s.id: s for s in step_list}
        t0 = time.time()
        progressed = True
        while progressed:
            progressed = False
            for s in steps.values():
                if s.status == "pending" and self._blocked_by_failure(s, steps):
                    s.status = "blocked"; progressed = True; continue
                if not self._ready(s, steps):
                    continue
                progressed = True
                if self.gate and not self.gate(s):        # governance pre-check
                    s.status = "blocked"; s.result = "gate: canon conflict"
                    continue
                agent = self.agents.get(s.assignee) or next(iter(self.agents.values()))
                # Observe: memory context; Orient/Decide are the agent's job; Act:
                ctx = self.m.context(s.goal, k=self.context_k) if self.m else ""
                deps = "\n".join(f"[{d}] {steps[d].result}" for d in s.depends_on if d in steps)
                prompt = f"{ctx}\n\nUPSTREAM RESULTS:\n{deps}\n\nTASK: {s.goal}".strip()
                s.status = "running"; s.attempts += 1
                try:
                    s.result = agent(prompt)
                    s.status = "done"
                    if self.m:  # ADD-only trace of what happened (auditable thread)
                        self.m.remember(f"step {s.id} [{s.assignee}] done: {s.result[:200]}",
                                        namespace="orchestrator", mtype="event")
                except Exception as e:
                    s.result = f"error: {e}"
                    s.status = "pending" if s.attempts < MAX_ATTEMPTS else "failed"
                    if s.status == "failed" and self.m:
                        self.m.remember(f"step {s.id} FAILED after {s.attempts}: {e}",
                                        namespace="orchestrator", mtype="error")
                if self.on_checkpoint:
                    try: self.on_checkpoint(s)
                    except Exception: pass
        done = sum(1 for s in steps.values() if s.status == "done")
        return {"steps": {k: {"status": v.status, "result": v.result[:300],
                              "attempts": v.attempts} for k, v in steps.items()},
                "done": done, "total": len(steps), "sec": round(time.time() - t0, 2),
                "ok": done == len(steps)}
