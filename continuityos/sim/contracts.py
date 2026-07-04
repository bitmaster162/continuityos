"""Sim-OS bridge contracts — Python mirror of the Rust SimulationSpec/Result (§1 of
AI Simulation OS Architecture). Deterministic boundary between ContinuityOS (stateful
control) and Pandora (stateless sim engine). 2026-07-04, cp-0318 scaffold (Fable 5).

These dataclasses are the versioned data contract. Keep field names in sync with the
Rust structs; add `contract_version` bumps on any breaking change.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
import hashlib
import json
import uuid

CONTRACT_VERSION = "0.1.0"


class OptimizationDirection(str, Enum):
    MAXIMIZE = "maximize"
    MINIMIZE = "minimize"
    TARGET = "target"          # hit target_value as closely as possible


class FailureMode(str, Enum):
    NONE = "none"
    CONSTRAINT_VIOLATION = "constraint_violation"
    BUDGET_EXHAUSTED = "budget_exhausted"
    HALLUCINATION_LOOP = "hallucination_loop"   # §4.1 semantic-entropy plateau
    DIVERGENCE = "divergence"
    ENGINE_ERROR = "engine_error"


class SimStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PLATEAU = "plateau"        # early-exit: no further improvement
    ABORTED = "aborted"


@dataclass
class Objective:
    primary_metric: str
    target_value: float
    optimization_direction: OptimizationDirection = OptimizationDirection.MAXIMIZE


@dataclass
class SimulationConstraints:
    """Boundary conditions — Pandora terminates on breach."""
    hard_bounds: Dict[str, float] = field(default_factory=dict)   # param -> abs max
    forbidden_regions: List[str] = field(default_factory=list)
    max_entities: int = 10_000


@dataclass
class ExecutionBudget:
    compute_tokens: int = 100_000
    wall_time_seconds: float = 300.0
    api_call_limit: int = 100


@dataclass
class StoppingCriteria:
    success_threshold: float          # metric value that counts as done
    failure_threshold: float          # metric value that counts as blown
    plateau_patience: int = 3         # iters w/o improvement before PLATEAU
    plateau_min_delta: float = 1e-4


@dataclass
class EntityState:
    entity_id: str
    attributes: Dict[str, float] = field(default_factory=dict)


@dataclass
class CanonicalState:
    """Verified world-state injected into the sim (operator canon, §1.1)."""
    entities: List[EntityState] = field(default_factory=list)
    as_of_epoch: float = 0.0          # bitemporal: what was true THEN


@dataclass
class SimulationSpec:
    """Immutable plan for one Pandora run. Built by ContinuityOS control plane
    only AFTER the governance gateway authorizes the intent."""
    objective: Objective
    parameters: Dict[str, float]
    constraints: SimulationConstraints
    budget: ExecutionBudget
    stopping_criteria: StoppingCriteria
    operator_canon: CanonicalState
    provenance: List[str] = field(default_factory=list)   # spec_ids Merkle-DAG
    spec_id: str = ""
    contract_version: str = CONTRACT_VERSION

    def finalize(self) -> "SimulationSpec":
        """Compute content-addressed spec_id: SHA-256 over ALL semantically material
        fields (P0-1 fix, GPT audit 2026-07-04). Two specs differing in budget,
        constraints, stopping criteria or operator canon MUST get different ids —
        otherwise spec_id can't back provenance/integrity claims."""
        import dataclasses
        payload = {
            "objective": self.objective.__dict__ | {
                "optimization_direction": self.objective.optimization_direction.value},
            "parameters": self.parameters,
            "constraints": dataclasses.asdict(self.constraints),
            "budget": dataclasses.asdict(self.budget),
            "stopping_criteria": dataclasses.asdict(self.stopping_criteria),
            "operator_canon": dataclasses.asdict(self.operator_canon),
            "provenance": self.provenance,
            "version": self.contract_version,
        }
        h = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        self.spec_id = h
        return self


@dataclass
class Anomaly:
    kind: str
    severity: float           # 0..1
    detail: str = ""


@dataclass
class ResourceConsumption:
    compute_tokens_used: int = 0
    wall_time_seconds: float = 0.0
    api_calls_used: int = 0


@dataclass
class NextCandidateRecommendation:
    """Pandora's suggestion for the next hypothesis (drives the OODA loop)."""
    parameters: Dict[str, float]
    expected_gain: float = 0.0
    rationale: str = ""


@dataclass
class SimulationResult:
    spec_id: str
    status: SimStatus
    metrics: Dict[str, float]
    failure_mode: FailureMode = FailureMode.NONE
    anomalies: List[Anomaly] = field(default_factory=list)
    resource_consumption: ResourceConsumption = field(default_factory=ResourceConsumption)
    next_candidate: Optional[NextCandidateRecommendation] = None
    result_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    contract_version: str = CONTRACT_VERSION
