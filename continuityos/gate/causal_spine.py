"""Deterministic causal-spine completeness gate.

LLMs may propose candidate frontiers, but this module alone evaluates whether the
minimum causal record is complete enough for downstream review. Passing this gate
never grants canon, source, deployment, runtime, trading, capital, or effect
authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence, Tuple


class CausalSpineStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE_ORIGIN = "INCOMPLETE_ORIGIN"
    INCOMPLETE_PIVOT = "INCOMPLETE_PIVOT"
    INCOMPLETE_CURRENT_STATE = "INCOMPLETE_CURRENT_STATE"
    SEARCH_INCOMPLETE = "SEARCH_INCOMPLETE"
    CONTRADICTED = "CONTRADICTED"
    SUPERSEDED = "SUPERSEDED"


class PivotStatus(str, Enum):
    FOUND = "FOUND"
    NO_MATERIAL_PIVOT_FOUND = "NO_MATERIAL_PIVOT_FOUND"
    SEARCH_INCOMPLETE = "SEARCH_INCOMPLETE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EvidenceRef:
    """Stable provenance binding to a provider object or immutable payload."""

    source_system: str
    object_id: str
    revision_id: Optional[str] = None
    sha256: Optional[str] = None
    locator: Optional[str] = None

    def is_bound(self) -> bool:
        return bool(
            self.source_system.strip()
            and self.object_id.strip()
            and (
                (self.revision_id is not None and self.revision_id.strip())
                or (self.sha256 is not None and self.sha256.strip())
            )
        )


@dataclass(frozen=True)
class Frontier:
    """Origin or material correction/pivot frontier proposed from evidence."""

    event_id: str
    evidence: Tuple[EvidenceRef, ...] = field(default_factory=tuple)

    def has_provenance(self) -> bool:
        return bool(self.event_id.strip()) and bool(self.evidence) and all(
            item.is_bound() for item in self.evidence
        )


@dataclass(frozen=True)
class BoundedSearchReceipt:
    """Proof that an explicit no-pivot conclusion came from a bounded search."""

    search_id: str
    scope: str
    sources_checked: Tuple[EvidenceRef, ...] = field(default_factory=tuple)
    completed: bool = False

    def is_complete(self) -> bool:
        return bool(
            self.completed
            and self.search_id.strip()
            and self.scope.strip()
            and self.sources_checked
            and all(item.is_bound() for item in self.sources_checked)
        )


@dataclass(frozen=True)
class CurrentPhysicalState:
    """Provider-bound observation of the current physical state."""

    provider: str
    state_id: str
    observed_at: str
    evidence: Tuple[EvidenceRef, ...] = field(default_factory=tuple)

    def has_provenance(self) -> bool:
        return bool(
            self.provider.strip()
            and self.state_id.strip()
            and self.observed_at.strip()
            and self.evidence
            and all(item.is_bound() for item in self.evidence)
        )


@dataclass(frozen=True)
class CausalSpine:
    spine_id: str
    subject_type: str
    subject_id: str
    origin: Optional[Frontier] = None
    pivot_status: PivotStatus = PivotStatus.UNKNOWN
    pivot: Optional[Frontier] = None
    pivot_search: Optional[BoundedSearchReceipt] = None
    current_state: Optional[CurrentPhysicalState] = None
    contradicted: bool = False
    superseded: bool = False


@dataclass(frozen=True)
class CausalGateResult:
    status: CausalSpineStatus
    missing_frontiers: Tuple[str, ...]
    causal_gate_passed: bool
    grants_canonical_authority: bool = False
    grants_effect_authority: bool = False

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "status": self.status.value,
            "missing_frontiers": list(self.missing_frontiers),
            "causal_gate_passed": self.causal_gate_passed,
            "grants_canonical_authority": self.grants_canonical_authority,
            "grants_effect_authority": self.grants_effect_authority,
        }


def evaluate_causal_spine(spine: CausalSpine) -> CausalGateResult:
    """Evaluate causal completeness in a fail-closed, deterministic order."""

    if spine.superseded:
        return _result(CausalSpineStatus.SUPERSEDED, ("superseded",))

    if spine.contradicted:
        return _result(CausalSpineStatus.CONTRADICTED, ("contradiction",))

    if spine.origin is None or not spine.origin.has_provenance():
        return _result(CausalSpineStatus.INCOMPLETE_ORIGIN, ("origin",))

    if spine.pivot_status is PivotStatus.SEARCH_INCOMPLETE:
        return _result(CausalSpineStatus.SEARCH_INCOMPLETE, ("pivot_search",))

    if spine.pivot_status is PivotStatus.FOUND:
        if spine.pivot is None or not spine.pivot.has_provenance():
            return _result(CausalSpineStatus.INCOMPLETE_PIVOT, ("pivot",))
    elif spine.pivot_status is PivotStatus.NO_MATERIAL_PIVOT_FOUND:
        if spine.pivot_search is None or not spine.pivot_search.is_complete():
            return _result(CausalSpineStatus.SEARCH_INCOMPLETE, ("pivot_search",))
    else:
        return _result(CausalSpineStatus.INCOMPLETE_PIVOT, ("pivot",))

    if spine.current_state is None or not spine.current_state.has_provenance():
        return _result(
            CausalSpineStatus.INCOMPLETE_CURRENT_STATE,
            ("current_physical_state",),
        )

    return CausalGateResult(
        status=CausalSpineStatus.COMPLETE,
        missing_frontiers=(),
        causal_gate_passed=True,
    )


def _result(
    status: CausalSpineStatus,
    missing_frontiers: Sequence[str],
) -> CausalGateResult:
    return CausalGateResult(
        status=status,
        missing_frontiers=tuple(missing_frontiers),
        causal_gate_passed=False,
    )
