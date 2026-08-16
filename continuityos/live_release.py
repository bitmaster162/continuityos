"""Provenance-gated LIVE release primitives for prospective SCT evaluation.

This module is intentionally generic and contains no principal-specific evidence.
It binds a separately adjudicated provenance release and a prospective opportunity
record to the existing LIVE-0.1 choice-contract/TwinBench flow.

It does not call models, reveal private evidence, execute actions, mutate canon, or
grant authority.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple
import hashlib
import json
import math
import time

LIVE_RELEASE_SCHEMA = "continuityos.sct.live-release/v1"
OPPORTUNITY_SCHEMA = "continuityos.sct.live-opportunity/v1"
RECEIPT_SCHEMA = "continuityos.sct.live-release-receipt/v1"
BASELINES = ("generic", "profile_rag", "sct")
AUTHORITY = "NONE"

DEFAULT_CORE_REQUIREMENTS: Mapping[str, Tuple[int, int]] = {
    "DS-001": (3, 2),
    "DS-002": (2, 2),
}


class LiveReleaseError(ValueError):
    """Raised when provenance or prospective-enrollment contracts are violated."""


def _cj(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(value: Any) -> str:
    raw = value if isinstance(value, str) else _cj(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LiveReleaseError(f"{field} must be a non-empty string")
    return value.strip()


def _sha256_hex(value: str, field: str) -> str:
    value = _text(value, field).lower()
    if len(value) != 64:
        raise LiveReleaseError(f"{field} must be a SHA-256 hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise LiveReleaseError(f"{field} must be a SHA-256 hex digest") from exc
    return value


def _ts(value: Optional[float], field: str) -> float:
    out = time.time() if value is None else float(value)
    if not math.isfinite(out):
        raise LiveReleaseError(f"{field} must be finite")
    return out


def _non_negative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LiveReleaseError(f"{field} must be a non-negative integer")
    return value


def _strength(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LiveReleaseError(f"{field} must be numeric")
    out = float(value)
    if not math.isfinite(out) or not 0.0 <= out <= 1.0:
        raise LiveReleaseError(f"{field} must be in [0,1]")
    return out


def _sanitize_feature(feature_id: str, raw: Mapping[str, Any]) -> Dict[str, Any]:
    feature_id = _text(feature_id, "feature_id")
    if not isinstance(raw, Mapping):
        raise LiveReleaseError(f"feature {feature_id} must be an object")
    state = _text(raw.get("state"), f"{feature_id}.state")
    gate_met = raw.get("gate_met")
    if not isinstance(gate_met, bool):
        raise LiveReleaseError(f"{feature_id}.gate_met must be boolean")
    accepted_decisions = _non_negative_int(
        raw.get("accepted_decisions"), f"{feature_id}.accepted_decisions"
    )
    independent_clusters = _non_negative_int(
        raw.get("independent_clusters"), f"{feature_id}.independent_clusters"
    )
    predictive_strength = _strength(
        raw.get("predictive_strength"), f"{feature_id}.predictive_strength"
    )
    if raw.get("execution_authority", AUTHORITY) != AUTHORITY:
        raise LiveReleaseError(f"{feature_id} cannot grant execution authority")
    return {
        "feature_id": feature_id,
        "state": state,
        "gate_met": gate_met,
        "accepted_decisions": accepted_decisions,
        "independent_clusters": independent_clusters,
        "predictive_strength": predictive_strength,
    }


def build_feature_release(
    *,
    parent_evidence_sha256: str,
    features: Mapping[str, Mapping[str, Any]],
    generated_at: Optional[float] = None,
    core_requirements: Optional[Mapping[str, Tuple[int, int]]] = None,
) -> Dict[str, Any]:
    """Build a privacy-minimized LIVE release from already adjudicated evidence.

    Only counts, cluster counts, state, strength, and the parent evidence hash are
    retained. Raw excerpts, message IDs, paths, and personal evidence are forbidden
    from this public release object.
    """
    parent_evidence_sha256 = _sha256_hex(
        parent_evidence_sha256, "parent_evidence_sha256"
    )
    if not isinstance(features, Mapping) or not features:
        raise LiveReleaseError("features must be a non-empty mapping")
    requirements = dict(core_requirements or DEFAULT_CORE_REQUIREMENTS)
    normalized = {fid: _sanitize_feature(fid, raw) for fid, raw in features.items()}

    for feature_id, pair in requirements.items():
        if (
            not isinstance(pair, (tuple, list))
            or len(pair) != 2
            or any(isinstance(x, bool) or not isinstance(x, int) or x < 1 for x in pair)
        ):
            raise LiveReleaseError(
                f"core requirement for {feature_id} must be (min_decisions, min_clusters)"
            )
        if feature_id not in normalized:
            raise LiveReleaseError(f"missing required core feature: {feature_id}")
        feature = normalized[feature_id]
        min_decisions, min_clusters = int(pair[0]), int(pair[1])
        if feature["state"] != "PROVENANCE_ADMITTED_PROVISIONAL":
            raise LiveReleaseError(f"{feature_id} is not provenance admitted")
        if feature["gate_met"] is not True:
            raise LiveReleaseError(f"{feature_id} gate is not met")
        if feature["accepted_decisions"] < min_decisions:
            raise LiveReleaseError(
                f"{feature_id} has insufficient direct-source decisions"
            )
        if feature["independent_clusters"] < min_clusters:
            raise LiveReleaseError(
                f"{feature_id} has insufficient independent clusters"
            )
        if feature["predictive_strength"] <= 0:
            raise LiveReleaseError(f"{feature_id} has no admitted predictive strength")

    generated_at = _ts(generated_at, "generated_at")
    body = {
        "schema": LIVE_RELEASE_SCHEMA,
        "parent_evidence_sha256": parent_evidence_sha256,
        "features": tuple(normalized[k] for k in sorted(normalized)),
        "core_requirements": tuple(
            (fid, int(req[0]), int(req[1])) for fid, req in sorted(requirements.items())
        ),
        "core_provenance_gate_met": True,
        "generated_at": generated_at,
        "mode": "SHADOW",
        "execution_authority": AUTHORITY,
        "can_execute": False,
    }
    out = dict(body)
    out["release_sha256"] = _sha(body)
    return out


def validate_feature_release(release: Mapping[str, Any]) -> None:
    if not isinstance(release, Mapping):
        raise LiveReleaseError("feature release must be an object")
    if release.get("schema") != LIVE_RELEASE_SCHEMA:
        raise LiveReleaseError("unsupported feature release schema")
    if release.get("core_provenance_gate_met") is not True:
        raise LiveReleaseError("core provenance gate is not open")
    if release.get("execution_authority") != AUTHORITY or release.get("can_execute") is not False:
        raise LiveReleaseError("feature release must remain shadow-only with no authority")
    expected = release.get("release_sha256")
    body = {k: release[k] for k in release if k != "release_sha256"}
    if _sha(body) != expected:
        raise LiveReleaseError("feature release hash mismatch")


def build_opportunity(
    *,
    opportunity_id: str,
    case_id: str,
    observed_at: Optional[float],
    decision_surface: str,
    situation: str,
    domains: Sequence[str],
    unresolved: bool = True,
    human_inclination_disclosed: bool = False,
    prior_assistant_recommendation: bool = False,
    actual_choice_known: bool = False,
    retrospective: bool = False,
    high_stakes_excluded: bool = False,
) -> Dict[str, Any]:
    """Register a clean prospective decision opportunity before prediction/reveal."""
    opportunity_id = _text(opportunity_id, "opportunity_id")
    case_id = _text(case_id, "case_id")
    decision_surface = _text(decision_surface, "decision_surface")
    situation = _text(situation, "situation")
    domains_t = tuple(dict.fromkeys(_text(x, "domains") for x in domains))
    if not domains_t:
        raise LiveReleaseError("domains must contain at least one value")
    observed_at = _ts(observed_at, "observed_at")

    flags = {
        "unresolved": unresolved,
        "human_inclination_disclosed": human_inclination_disclosed,
        "prior_assistant_recommendation": prior_assistant_recommendation,
        "actual_choice_known": actual_choice_known,
        "retrospective": retrospective,
        "high_stakes_excluded": high_stakes_excluded,
    }
    if any(not isinstance(v, bool) for v in flags.values()):
        raise LiveReleaseError("opportunity flags must be boolean")
    if unresolved is not True:
        raise LiveReleaseError("opportunity must be unresolved at observation")
    if human_inclination_disclosed:
        raise LiveReleaseError("human inclination leakage")
    if prior_assistant_recommendation:
        raise LiveReleaseError("prior assistant recommendation contamination")
    if actual_choice_known:
        raise LiveReleaseError("actual choice is already known")
    if retrospective:
        raise LiveReleaseError("retrospective cases are not prospective LIVE")
    if high_stakes_excluded:
        raise LiveReleaseError("excluded high-stakes domain")

    body = {
        "schema": OPPORTUNITY_SCHEMA,
        "opportunity_id": opportunity_id,
        "case_id": case_id,
        "observed_at": observed_at,
        "decision_surface": decision_surface,
        "situation_sha256": _sha(situation),
        "domains": domains_t,
        "unresolved": True,
        "human_inclination_disclosed": False,
        "prior_assistant_recommendation": False,
        "actual_choice_known": False,
        "retrospective": False,
        "high_stakes_excluded": False,
        "mode": "SHADOW",
        "execution_authority": AUTHORITY,
        "can_execute": False,
    }
    out = dict(body)
    out["opportunity_sha256"] = _sha(body)
    return out


def validate_opportunity(opportunity: Mapping[str, Any]) -> None:
    if not isinstance(opportunity, Mapping):
        raise LiveReleaseError("opportunity must be an object")
    if opportunity.get("schema") != OPPORTUNITY_SCHEMA:
        raise LiveReleaseError("unsupported opportunity schema")
    if opportunity.get("unresolved") is not True:
        raise LiveReleaseError("opportunity is not unresolved")
    for forbidden in (
        "human_inclination_disclosed",
        "prior_assistant_recommendation",
        "actual_choice_known",
        "retrospective",
        "high_stakes_excluded",
    ):
        if opportunity.get(forbidden) is not False:
            raise LiveReleaseError(f"opportunity contamination: {forbidden}")
    if opportunity.get("execution_authority") != AUTHORITY or opportunity.get("can_execute") is not False:
        raise LiveReleaseError("opportunity must remain shadow-only with no authority")
    expected = opportunity.get("opportunity_sha256")
    body = {k: opportunity[k] for k in opportunity if k != "opportunity_sha256"}
    if _sha(body) != expected:
        raise LiveReleaseError("opportunity hash mismatch")


def _snapshot_hash(value: Any, name: str) -> str:
    raw = value.snapshot_sha256 if hasattr(value, "snapshot_sha256") else value
    return _sha256_hex(raw, f"input_snapshot_sha256[{name}]")


def build_release_receipt(
    *,
    case_id: str,
    decision_surface: str,
    situation: str,
    choice_contract_sha256: str,
    frozen_inputs: Mapping[str, Any],
    feature_release: Mapping[str, Any],
    opportunity: Mapping[str, Any],
    bound_at: Optional[float] = None,
) -> Dict[str, Any]:
    """Bind the release and opportunity to one already frozen A/B/C case."""
    validate_feature_release(feature_release)
    validate_opportunity(opportunity)
    case_id = _text(case_id, "case_id")
    decision_surface = _text(decision_surface, "decision_surface")
    situation = _text(situation, "situation")
    choice_contract_sha256 = _sha256_hex(
        choice_contract_sha256, "choice_contract_sha256"
    )
    if opportunity.get("case_id") != case_id:
        raise LiveReleaseError("opportunity case_id does not match LIVE case")
    if opportunity.get("decision_surface") != decision_surface:
        raise LiveReleaseError("opportunity decision_surface does not match LIVE case")
    if opportunity.get("situation_sha256") != _sha(situation):
        raise LiveReleaseError("opportunity situation does not match LIVE case")
    if set(frozen_inputs) != set(BASELINES):
        raise LiveReleaseError(f"frozen_inputs must contain exactly {BASELINES}")
    input_hashes = {
        name: _snapshot_hash(frozen_inputs[name], name) for name in BASELINES
    }
    body = {
        "schema": RECEIPT_SCHEMA,
        "case_id": case_id,
        "opportunity_id": opportunity["opportunity_id"],
        "opportunity_sha256": opportunity["opportunity_sha256"],
        "feature_release_sha256": feature_release["release_sha256"],
        "choice_contract_sha256": choice_contract_sha256,
        "input_snapshot_sha256": input_hashes,
        "bound_at": _ts(bound_at, "bound_at"),
        "mode": "SHADOW",
        "execution_authority": AUTHORITY,
        "can_execute": False,
    }
    out = dict(body)
    out["receipt_sha256"] = _sha(body)
    return out


def prepare_released_live_case(
    *,
    arena: Any,
    root: str | Path,
    case_id: str,
    decision_surface: str,
    situation: str,
    choice_contract: Any,
    frozen_inputs: Mapping[str, Any],
    feature_release: Mapping[str, Any],
    opportunity: Mapping[str, Any],
    eligibility: Any = None,
    opened_at: Optional[float] = None,
    case_preparer: Optional[Callable[..., Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """Prepare LIVE-1 via the existing LIVE-0.1 preparer plus release binding."""
    validate_feature_release(feature_release)
    validate_opportunity(opportunity)
    if case_preparer is None:
        from .live_choice_contract import prepare_contracted_live_case
        case_preparer = prepare_contracted_live_case

    prepared = case_preparer(
        arena,
        root=root,
        case_id=case_id,
        decision_surface=decision_surface,
        situation=situation,
        choice_contract=choice_contract,
        frozen_inputs=frozen_inputs,
        eligibility=eligibility,
        opened_at=opened_at,
    )
    try:
        contract_sha = prepared["choice_contract"]["contract_sha256"]
    except (KeyError, TypeError) as exc:
        raise LiveReleaseError("case preparer did not return a choice contract hash") from exc

    receipt = build_release_receipt(
        case_id=case_id,
        decision_surface=decision_surface,
        situation=situation,
        choice_contract_sha256=contract_sha,
        frozen_inputs=frozen_inputs,
        feature_release=feature_release,
        opportunity=opportunity,
        bound_at=opened_at,
    )

    case_dir = Path(root) / case_id
    if not case_dir.exists():
        raise LiveReleaseError("case preparer did not create the case directory")
    (case_dir / "live_release_receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return {
        "prepared_case": prepared,
        "live_release_receipt": receipt,
    }
