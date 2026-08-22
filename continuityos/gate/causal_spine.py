"""Deterministic, evidence-bound causal-spine completeness gate.

Causal completeness is deliberately narrower than truth acceptance or effect
authority. A complete causal spine proves that three evidence-bound frontiers
exist: origin, material correction/pivot (or bounded no-pivot proof), and a
provider-bound current physical state. It never grants source, canonical,
merge, deployment, runtime, trading, capital, messaging, or other effect
authority.

LLMs may propose candidate frontiers. This module performs deterministic
validation only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import re
from typing import Any, Mapping, Optional, Sequence, Tuple

from .evidence_common import canonical_json_text, fixed_effects

SPINE_SCHEMA = "continuityos.causal_spine/v1"
RECEIPT_SCHEMA = "continuityos.causal_spine.receipt/v1"
EVENT_SCHEMA = "continuityos.causal_spine.event/v1"
STATE_RESOLUTION_PASS = "STATE_RESOLUTION_PASS"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _parse_time(value: Any) -> Optional[datetime]:
    if not _nonempty(value):
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class EvidenceRef:
    """Stable provenance binding to a provider object or immutable payload."""

    source_system: str
    object_id: str
    revision_id: Optional[str] = None
    sha256: Optional[str] = None
    locator: Optional[str] = None

    def is_bound(self) -> bool:
        if not (_nonempty(self.source_system) and _nonempty(self.object_id)):
            return False
        revision_bound = self.revision_id is not None and _nonempty(self.revision_id)
        sha_bound = self.sha256 is not None and bool(SHA256_RE.fullmatch(self.sha256))
        if not (revision_bound or sha_bound):
            return False
        if self.locator is not None and not _nonempty(self.locator):
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_system": self.source_system,
            "object_id": self.object_id,
            "revision_id": self.revision_id,
            "sha256": self.sha256,
            "locator": self.locator,
        }


@dataclass(frozen=True)
class Frontier:
    event_id: str
    evidence: Tuple[EvidenceRef, ...] = field(default_factory=tuple)

    def has_provenance(self) -> bool:
        return _nonempty(self.event_id) and bool(self.evidence) and all(
            item.is_bound() for item in self.evidence
        )

    def to_dict(self) -> dict[str, Any]:
        return {"event_id": self.event_id, "evidence": [item.to_dict() for item in self.evidence]}


@dataclass(frozen=True)
class BoundedSearchReceipt:
    search_id: str
    scope: str
    sources_checked: Tuple[EvidenceRef, ...] = field(default_factory=tuple)
    completed: bool = False
    completed_at: Optional[str] = None

    def is_complete(self) -> bool:
        return bool(
            self.completed
            and _nonempty(self.search_id)
            and _nonempty(self.scope)
            and self.sources_checked
            and all(item.is_bound() for item in self.sources_checked)
            and _parse_time(self.completed_at) is not None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "search_id": self.search_id,
            "scope": self.scope,
            "sources_checked": [item.to_dict() for item in self.sources_checked],
            "completed": self.completed,
            "completed_at": self.completed_at,
        }


@dataclass(frozen=True)
class CurrentPhysicalState:
    """Provider-bound current observation tied to one state-resolution artifact."""

    provider: str
    state_id: str
    observed_at: str
    evidence: Tuple[EvidenceRef, ...] = field(default_factory=tuple)
    resolution_artifact_id: Optional[str] = None
    resolution_artifact_sha256: Optional[str] = None

    def has_provenance(self) -> bool:
        if not (
            _nonempty(self.provider)
            and _nonempty(self.state_id)
            and _parse_time(self.observed_at) is not None
            and self.evidence
            and all(item.is_bound() for item in self.evidence)
            and _nonempty(self.resolution_artifact_id)
            and isinstance(self.resolution_artifact_sha256, str)
            and SHA256_RE.fullmatch(self.resolution_artifact_sha256)
        ):
            return False
        provider = self.provider.strip().casefold()
        return any(item.source_system.strip().casefold() == provider for item in self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "state_id": self.state_id,
            "observed_at": self.observed_at,
            "evidence": [item.to_dict() for item in self.evidence],
            "resolution_artifact_id": self.resolution_artifact_id,
            "resolution_artifact_sha256": self.resolution_artifact_sha256,
        }


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
    contradiction_evidence: Tuple[EvidenceRef, ...] = field(default_factory=tuple)
    superseded: bool = False
    superseded_by: Optional[EvidenceRef] = None

    def identity_valid(self) -> bool:
        return all(_nonempty(item) for item in (self.spine_id, self.subject_type, self.subject_id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SPINE_SCHEMA,
            "spine_id": self.spine_id,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "origin": self.origin.to_dict() if self.origin else None,
            "pivot_status": self.pivot_status.value,
            "pivot": self.pivot.to_dict() if self.pivot else None,
            "pivot_search": self.pivot_search.to_dict() if self.pivot_search else None,
            "current_state": self.current_state.to_dict() if self.current_state else None,
            "contradicted": self.contradicted,
            "contradiction_evidence": [item.to_dict() for item in self.contradiction_evidence],
            "superseded": self.superseded,
            "superseded_by": self.superseded_by.to_dict() if self.superseded_by else None,
        }


@dataclass(frozen=True)
class CausalGateResult:
    status: CausalSpineStatus
    reason_code: str
    missing_frontiers: Tuple[str, ...]
    causal_gate_passed: bool
    state_resolution_terminal: Optional[str] = None
    grants_source_authority: bool = False
    grants_canonical_authority: bool = False
    grants_merge_authority: bool = False
    grants_deploy_authority: bool = False
    grants_runtime_authority: bool = False
    grants_effect_authority: bool = False

    @property
    def terminal(self) -> str:
        return "CAUSAL_SPINE_PASS" if self.causal_gate_passed else "CAUSAL_SPINE_INCOMPLETE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": RECEIPT_SCHEMA,
            "terminal": self.terminal,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "missing_frontiers": list(self.missing_frontiers),
            "causal_gate_passed": self.causal_gate_passed,
            "state_resolution_terminal": self.state_resolution_terminal,
            "grants_source_authority": self.grants_source_authority,
            "grants_canonical_authority": self.grants_canonical_authority,
            "grants_merge_authority": self.grants_merge_authority,
            "grants_deploy_authority": self.grants_deploy_authority,
            "grants_runtime_authority": self.grants_runtime_authority,
            "grants_effect_authority": self.grants_effect_authority,
            "effects": fixed_effects(),
        }


def _result(
    status: CausalSpineStatus,
    reason_code: str,
    missing_frontiers: Sequence[str] = (),
    *,
    state_resolution_terminal: Optional[str] = None,
) -> CausalGateResult:
    return CausalGateResult(
        status=status,
        reason_code=reason_code,
        missing_frontiers=tuple(missing_frontiers),
        causal_gate_passed=False,
        state_resolution_terminal=state_resolution_terminal,
    )


def _current_state_resolution_check(
    current: CurrentPhysicalState,
    resolution: Optional[Mapping[str, Any]],
) -> Optional[CausalGateResult]:
    if resolution is None:
        return _result(
            CausalSpineStatus.INCOMPLETE_CURRENT_STATE,
            "CURRENT_STATE_RESOLUTION_REQUIRED",
            ("current_physical_state_resolution",),
        )
    terminal = resolution.get("terminal")
    if terminal != STATE_RESOLUTION_PASS:
        reason = str(resolution.get("reason") or "")
        contradicted = "CONTRADICTION" in reason.upper()
        return _result(
            CausalSpineStatus.CONTRADICTED if contradicted else CausalSpineStatus.INCOMPLETE_CURRENT_STATE,
            "CURRENT_STATE_CONTRADICTED" if contradicted else "CURRENT_STATE_RESOLUTION_NOT_PASS",
            ("current_physical_state_resolution",),
            state_resolution_terminal=str(terminal) if terminal is not None else None,
        )
    selected = resolution.get("selected")
    if not isinstance(selected, Mapping):
        return _result(
            CausalSpineStatus.INCOMPLETE_CURRENT_STATE,
            "CURRENT_STATE_RESOLUTION_SELECTED_MISSING",
            ("current_physical_state_resolution",),
            state_resolution_terminal=str(terminal),
        )
    if selected.get("kind") != "PROVIDER_READBACK":
        return _result(
            CausalSpineStatus.INCOMPLETE_CURRENT_STATE,
            "CURRENT_STATE_NOT_PROVIDER_READBACK",
            ("current_physical_state",),
            state_resolution_terminal=str(terminal),
        )
    if selected.get("artifact_id") != current.resolution_artifact_id:
        return _result(
            CausalSpineStatus.INCOMPLETE_CURRENT_STATE,
            "CURRENT_STATE_ARTIFACT_ID_MISMATCH",
            ("current_physical_state",),
            state_resolution_terminal=str(terminal),
        )
    if selected.get("artifact_sha256") != current.resolution_artifact_sha256:
        return _result(
            CausalSpineStatus.INCOMPLETE_CURRENT_STATE,
            "CURRENT_STATE_ARTIFACT_SHA_MISMATCH",
            ("current_physical_state",),
            state_resolution_terminal=str(terminal),
        )
    selected_time = _parse_time(selected.get("observed_at_utc"))
    current_time = _parse_time(current.observed_at)
    if selected_time is None or current_time is None or selected_time != current_time:
        return _result(
            CausalSpineStatus.INCOMPLETE_CURRENT_STATE,
            "CURRENT_STATE_OBSERVATION_TIME_MISMATCH",
            ("current_physical_state",),
            state_resolution_terminal=str(terminal),
        )
    return None


def evaluate_causal_spine(
    spine: CausalSpine,
    *,
    current_state_resolution: Optional[Mapping[str, Any]] = None,
) -> CausalGateResult:
    """Evaluate causal completeness in deterministic fail-closed order."""

    if not spine.identity_valid():
        return _result(CausalSpineStatus.INCOMPLETE_ORIGIN, "SPINE_IDENTITY_INVALID", ("identity",))

    if spine.superseded:
        if spine.superseded_by is None or not spine.superseded_by.is_bound():
            return _result(CausalSpineStatus.SUPERSEDED, "SUPERSESSION_EVIDENCE_MISSING", ("supersession",))
        return _result(CausalSpineStatus.SUPERSEDED, "SPINE_SUPERSEDED", ("superseded",))

    if spine.contradicted:
        if not spine.contradiction_evidence or not all(item.is_bound() for item in spine.contradiction_evidence):
            return _result(CausalSpineStatus.CONTRADICTED, "CONTRADICTION_EVIDENCE_MISSING", ("contradiction",))
        return _result(CausalSpineStatus.CONTRADICTED, "SPINE_CONTRADICTED", ("contradiction",))

    if spine.origin is None or not spine.origin.has_provenance():
        return _result(CausalSpineStatus.INCOMPLETE_ORIGIN, "ORIGIN_MISSING_OR_UNBOUND", ("origin",))

    if spine.pivot_status is PivotStatus.SEARCH_INCOMPLETE:
        return _result(CausalSpineStatus.SEARCH_INCOMPLETE, "PIVOT_SEARCH_INCOMPLETE", ("pivot_search",))

    if spine.pivot_status is PivotStatus.FOUND:
        if spine.pivot is None or not spine.pivot.has_provenance():
            return _result(CausalSpineStatus.INCOMPLETE_PIVOT, "PIVOT_MISSING_OR_UNBOUND", ("pivot",))
    elif spine.pivot_status is PivotStatus.NO_MATERIAL_PIVOT_FOUND:
        if spine.pivot_search is None or not spine.pivot_search.is_complete():
            return _result(CausalSpineStatus.SEARCH_INCOMPLETE, "NO_PIVOT_SEARCH_PROOF_INCOMPLETE", ("pivot_search",))
    else:
        return _result(CausalSpineStatus.INCOMPLETE_PIVOT, "PIVOT_STATUS_UNKNOWN", ("pivot",))

    if spine.current_state is None or not spine.current_state.has_provenance():
        return _result(
            CausalSpineStatus.INCOMPLETE_CURRENT_STATE,
            "CURRENT_PHYSICAL_STATE_MISSING_OR_UNBOUND",
            ("current_physical_state",),
        )

    resolution_failure = _current_state_resolution_check(spine.current_state, current_state_resolution)
    if resolution_failure is not None:
        return resolution_failure

    return CausalGateResult(
        status=CausalSpineStatus.COMPLETE,
        reason_code="CAUSAL_FRONTIERS_COMPLETE_AND_PROVIDER_BOUND",
        missing_frontiers=(),
        causal_gate_passed=True,
        state_resolution_terminal=STATE_RESOLUTION_PASS,
    )


def resolve_and_evaluate_causal_spine(
    spine: CausalSpine,
    state_candidates: Sequence[Mapping[str, Any]],
) -> CausalGateResult:
    """Resolve current physical state using the existing state resolver, then gate."""
    from .state_resolution import resolve_state

    resolution = resolve_state(state_candidates)
    return evaluate_causal_spine(spine, current_state_resolution=resolution)


def build_evaluation_event(
    spine: CausalSpine,
    result: CausalGateResult,
    *,
    sequence: int,
    actor_id: str,
    recorded_at_utc: str,
    prev_event_sha256: Optional[str] = None,
) -> dict[str, Any]:
    """Build one append-only hash-chain event; performs no storage write."""

    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise ValueError("sequence must be a non-negative integer")
    if not _nonempty(actor_id):
        raise ValueError("actor_id must be non-empty")
    if _parse_time(recorded_at_utc) is None:
        raise ValueError("recorded_at_utc must be timezone-aware RFC3339")
    if prev_event_sha256 is not None and not SHA256_RE.fullmatch(prev_event_sha256):
        raise ValueError("prev_event_sha256 must be lowercase SHA-256 or null")

    core = {
        "schema": EVENT_SCHEMA,
        "sequence": sequence,
        "event_type": "CAUSAL_SPINE_EVALUATED",
        "recorded_at_utc": recorded_at_utc,
        "actor": {"role": "CAUSAL_SPINE_GATE", "id": actor_id},
        "spine_id": spine.spine_id,
        "subject_type": spine.subject_type,
        "subject_id": spine.subject_id,
        "spine_sha256": hashlib.sha256(
            canonical_json_text(spine.to_dict()).encode("utf-8")
        ).hexdigest(),
        "result": result.to_dict(),
        "prev_event_sha256": prev_event_sha256,
        "effects": fixed_effects(),
    }
    return {
        **core,
        "event_sha256": hashlib.sha256(canonical_json_text(core).encode("utf-8")).hexdigest(),
    }


def verify_evaluation_event(
    event: Mapping[str, Any],
    *,
    expected_prev_event_sha256: Optional[str] = None,
) -> bool:
    """Verify one event readback and optional chain predecessor identity."""

    if event.get("schema") != EVENT_SCHEMA:
        return False
    observed = event.get("event_sha256")
    if not isinstance(observed, str) or not SHA256_RE.fullmatch(observed):
        return False
    if expected_prev_event_sha256 is not None and event.get("prev_event_sha256") != expected_prev_event_sha256:
        return False
    core = dict(event)
    core.pop("event_sha256", None)
    expected = hashlib.sha256(canonical_json_text(core).encode("utf-8")).hexdigest()
    return observed == expected
