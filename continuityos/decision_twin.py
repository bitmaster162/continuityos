"""Shadow-only Decision Twin primitives for falsifiable personal-model evaluation.

SCT-R1 deliberately does not execute actions and does not grant authority.  It only
commits a prediction *before* the human decision, records the later human decision,
and scores prediction-vs-reality with an append-only hash-chained JSONL ledger.

The prediction model is intentionally external: a frontier LLM, the historical
``Twin`` class, or a deterministic rule engine can all produce a candidate choice.
This module owns the evidence contract, not the cognition.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import hashlib
import json
import math
import time

SCHEMA_VERSION = "continuityos.sct.decision-shadow/v1"
AUTHORITY = "NONE"
MODE = "SHADOW"


class DecisionTwinError(ValueError):
    """Raised when the shadow Decision Twin evidence contract is violated."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    raw = value if isinstance(value, str) else _canonical_json(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _clean_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DecisionTwinError(f"{field} must be a non-empty string")
    return value.strip()


def _clean_items(values: Optional[Iterable[str]], field: str) -> Tuple[str, ...]:
    out: List[str] = []
    for value in values or ():
        item = _clean_text(value, field)
        if item not in out:
            out.append(item)
    return tuple(out)


def _prediction_identity_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    keys = (
        "schema", "case_id", "situation", "options", "predicted_choice", "confidence",
        "reasons", "evidence_refs", "change_conditions", "would_escalate",
        "twin_snapshot_id", "model_id", "created_at", "mode", "execution_authority",
        "can_execute",
    )
    return {key: payload[key] for key in keys}


def _decision_identity_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    keys = (
        "schema", "case_id", "prediction_id", "actual_choice", "reasons",
        "decided_at", "source",
    )
    return {key: payload[key] for key in keys}


def _clean_confidence(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DecisionTwinError("confidence must be a finite number in [0, 1]")
    value = float(value)
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise DecisionTwinError("confidence must be a finite number in [0, 1]")
    return value


@dataclass(frozen=True)
class TwinPrediction:
    case_id: str
    situation: str
    options: Tuple[str, ...]
    predicted_choice: str
    confidence: float
    reasons: Tuple[str, ...]
    evidence_refs: Tuple[str, ...]
    change_conditions: Tuple[str, ...]
    would_escalate: bool
    twin_snapshot_id: Optional[str]
    model_id: Optional[str]
    created_at: float
    prediction_id: str
    schema: str = SCHEMA_VERSION
    mode: str = MODE
    execution_authority: str = AUTHORITY
    can_execute: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HumanDecision:
    case_id: str
    prediction_id: str
    actual_choice: str
    reasons: Tuple[str, ...]
    decided_at: float
    decision_id: str
    schema: str = SCHEMA_VERSION
    source: str = "HUMAN"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TwinEvaluation:
    case_id: str
    prediction_id: str
    decision_id: str
    correct: bool
    confidence: float
    absolute_calibration_error: float
    squared_calibration_error: float
    escalated: bool
    evaluated_at: float
    schema: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_prediction(
    *,
    case_id: str,
    situation: str,
    options: Sequence[str],
    predicted_choice: str,
    confidence: float,
    reasons: Optional[Iterable[str]] = None,
    evidence_refs: Optional[Iterable[str]] = None,
    change_conditions: Optional[Iterable[str]] = None,
    would_escalate: bool = False,
    twin_snapshot_id: Optional[str] = None,
    model_id: Optional[str] = None,
    created_at: Optional[float] = None,
) -> TwinPrediction:
    """Build an immutable shadow prediction whose ID commits to its exact contents."""
    case_id = _clean_text(case_id, "case_id")
    situation = _clean_text(situation, "situation")
    options_t = _clean_items(options, "options")
    if len(options_t) < 2:
        raise DecisionTwinError("options must contain at least two distinct choices")
    predicted_choice = _clean_text(predicted_choice, "predicted_choice")
    if predicted_choice not in options_t:
        raise DecisionTwinError("predicted_choice must be one of options")
    confidence = _clean_confidence(confidence)
    if not isinstance(would_escalate, bool):
        raise DecisionTwinError("would_escalate must be boolean")
    ts = time.time() if created_at is None else float(created_at)
    if not math.isfinite(ts):
        raise DecisionTwinError("created_at must be finite")
    payload = {
        "schema": SCHEMA_VERSION,
        "case_id": case_id,
        "situation": situation,
        "options": options_t,
        "predicted_choice": predicted_choice,
        "confidence": confidence,
        "reasons": _clean_items(reasons, "reasons"),
        "evidence_refs": _clean_items(evidence_refs, "evidence_refs"),
        "change_conditions": _clean_items(change_conditions, "change_conditions"),
        "would_escalate": would_escalate,
        "twin_snapshot_id": twin_snapshot_id,
        "model_id": model_id,
        "created_at": ts,
        "mode": MODE,
        "execution_authority": AUTHORITY,
        "can_execute": False,
    }
    return TwinPrediction(prediction_id=_sha256(_prediction_identity_payload(payload)), **{
        key: payload[key] for key in (
            "case_id", "situation", "options", "predicted_choice", "confidence",
            "reasons", "evidence_refs", "change_conditions", "would_escalate",
            "twin_snapshot_id", "model_id", "created_at"
        )
    })


def build_human_decision(
    prediction: TwinPrediction,
    *,
    actual_choice: str,
    reasons: Optional[Iterable[str]] = None,
    decided_at: Optional[float] = None,
) -> HumanDecision:
    """Bind a later human decision to one already-created prediction."""
    actual_choice = _clean_text(actual_choice, "actual_choice")
    if actual_choice not in prediction.options:
        raise DecisionTwinError("actual_choice must be one of prediction.options")
    ts = time.time() if decided_at is None else float(decided_at)
    if not math.isfinite(ts) or ts < prediction.created_at:
        raise DecisionTwinError("human decision must occur at or after prediction creation")
    payload = {
        "schema": SCHEMA_VERSION,
        "case_id": prediction.case_id,
        "prediction_id": prediction.prediction_id,
        "actual_choice": actual_choice,
        "reasons": _clean_items(reasons, "reasons"),
        "decided_at": ts,
        "source": "HUMAN",
    }
    return HumanDecision(decision_id=_sha256(_decision_identity_payload(payload)), **{
        key: payload[key] for key in (
            "case_id", "prediction_id", "actual_choice", "reasons", "decided_at"
        )
    })


def evaluate(prediction: TwinPrediction, decision: HumanDecision, *, evaluated_at: Optional[float] = None) -> TwinEvaluation:
    """Score one frozen prediction against its later human decision."""
    if prediction.prediction_id != decision.prediction_id or prediction.case_id != decision.case_id:
        raise DecisionTwinError("decision does not refer to this prediction")
    if decision.decided_at < prediction.created_at:
        raise DecisionTwinError("decision predates prediction")
    correct = prediction.predicted_choice == decision.actual_choice
    target = 1.0 if correct else 0.0
    abs_err = abs(prediction.confidence - target)
    sq_err = (prediction.confidence - target) ** 2
    ts = time.time() if evaluated_at is None else float(evaluated_at)
    if not math.isfinite(ts) or ts < decision.decided_at:
        raise DecisionTwinError("evaluation must occur at or after the human decision")
    return TwinEvaluation(
        case_id=prediction.case_id,
        prediction_id=prediction.prediction_id,
        decision_id=decision.decision_id,
        correct=correct,
        confidence=prediction.confidence,
        absolute_calibration_error=round(abs_err, 12),
        squared_calibration_error=round(sq_err, 12),
        escalated=prediction.would_escalate,
        evaluated_at=ts,
    )


class ShadowDecisionLedger:
    """Single-process append-only JSONL evidence ledger with a SHA-256 hash chain."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _rows(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        rows: List[Dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise DecisionTwinError(f"invalid ledger JSON at line {lineno}") from exc
        return rows

    def append(self, kind: str, payload: Dict[str, Any], *, ts: Optional[float] = None) -> Dict[str, Any]:
        kind = _clean_text(kind, "kind")
        if not isinstance(payload, dict):
            raise DecisionTwinError("payload must be an object")
        rows = self._rows()
        if rows:
            checked = self.verify()
            if not checked["ok"]:
                raise DecisionTwinError(f"refusing append to invalid ledger: {checked['error']}")
        prev_hash = rows[-1]["event_hash"] if rows else None
        seq = len(rows) + 1
        event_ts = time.time() if ts is None else float(ts)
        if not math.isfinite(event_ts):
            raise DecisionTwinError("event timestamp must be finite")
        body = {
            "schema": SCHEMA_VERSION,
            "seq": seq,
            "kind": kind,
            "ts": event_ts,
            "payload": payload,
            "prev_hash": prev_hash,
        }
        event = dict(body)
        event["event_hash"] = _sha256(body)
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(_canonical_json(event) + "\n")
            fh.flush()
        return event

    def commit_prediction(self, prediction: TwinPrediction) -> Dict[str, Any]:
        if self.find_prediction(prediction.prediction_id) is not None:
            raise DecisionTwinError("prediction is already committed")
        return self.append("TWIN_PREDICTION_COMMITTED", prediction.to_dict(), ts=prediction.created_at)

    def record_human_decision(self, decision: HumanDecision) -> Dict[str, Any]:
        pred = self.find_prediction(decision.prediction_id)
        if pred is None:
            raise DecisionTwinError("prediction must be committed before the human decision")
        if any(r["kind"] == "HUMAN_DECISION_RECORDED" and r["payload"].get("prediction_id") == decision.prediction_id for r in self._rows()):
            raise DecisionTwinError("human decision for this prediction is already recorded")
        if decision.decided_at < float(pred["created_at"]):
            raise DecisionTwinError("human decision predates committed prediction")
        return self.append("HUMAN_DECISION_RECORDED", decision.to_dict(), ts=decision.decided_at)

    def record_evaluation(self, result: TwinEvaluation) -> Dict[str, Any]:
        pred = self.find_prediction(result.prediction_id)
        decision = self.find_decision(result.prediction_id)
        if pred is None or decision is None:
            raise DecisionTwinError("prediction and human decision must be committed before evaluation")
        if result.decision_id != decision.get("decision_id"):
            raise DecisionTwinError("evaluation does not match committed human decision")
        if any(r["kind"] == "TWIN_EVALUATION_RECORDED" and r["payload"].get("prediction_id") == result.prediction_id for r in self._rows()):
            raise DecisionTwinError("evaluation for this prediction is already recorded")
        return self.append("TWIN_EVALUATION_RECORDED", result.to_dict(), ts=result.evaluated_at)

    def find_prediction(self, prediction_id: str) -> Optional[Dict[str, Any]]:
        for row in self._rows():
            if row["kind"] == "TWIN_PREDICTION_COMMITTED" and row["payload"].get("prediction_id") == prediction_id:
                return row["payload"]
        return None

    def find_decision(self, prediction_id: str) -> Optional[Dict[str, Any]]:
        for row in self._rows():
            if row["kind"] == "HUMAN_DECISION_RECORDED" and row["payload"].get("prediction_id") == prediction_id:
                return row["payload"]
        return None

    def evaluations(self) -> List[Dict[str, Any]]:
        return [r["payload"] for r in self._rows() if r["kind"] == "TWIN_EVALUATION_RECORDED"]

    def summary(self) -> Dict[str, Any]:
        ev = self.evaluations()
        n = len(ev)
        if not n:
            return {
                "count": 0,
                "accuracy": None,
                "mean_confidence": None,
                "mean_absolute_calibration_error": None,
                "mean_squared_calibration_error": None,
                "escalation_rate": None,
            }
        return {
            "count": n,
            "accuracy": sum(1 for x in ev if x["correct"]) / n,
            "mean_confidence": sum(float(x["confidence"]) for x in ev) / n,
            "mean_absolute_calibration_error": sum(float(x["absolute_calibration_error"]) for x in ev) / n,
            "mean_squared_calibration_error": sum(float(x["squared_calibration_error"]) for x in ev) / n,
            "escalation_rate": sum(1 for x in ev if x["escalated"]) / n,
        }

    def verify(self) -> Dict[str, Any]:
        rows = self._rows()
        prev_hash: Optional[str] = None
        for expected_seq, row in enumerate(rows, 1):
            required = {"schema", "seq", "kind", "ts", "payload", "prev_hash", "event_hash"}
            if set(row) != required:
                return {"ok": False, "count": len(rows), "error": f"shape mismatch at seq {expected_seq}"}
            if row["schema"] != SCHEMA_VERSION or row["seq"] != expected_seq or row["prev_hash"] != prev_hash:
                return {"ok": False, "count": len(rows), "error": f"chain mismatch at seq {expected_seq}"}
            body = {k: row[k] for k in ("schema", "seq", "kind", "ts", "payload", "prev_hash")}
            if _sha256(body) != row["event_hash"]:
                return {"ok": False, "count": len(rows), "error": f"hash mismatch at seq {expected_seq}"}
            payload = row["payload"]
            if row["kind"] == "TWIN_PREDICTION_COMMITTED":
                try:
                    if _sha256(_prediction_identity_payload(payload)) != payload["prediction_id"]:
                        return {"ok": False, "count": len(rows), "error": f"prediction identity mismatch at seq {expected_seq}"}
                except (KeyError, TypeError):
                    return {"ok": False, "count": len(rows), "error": f"prediction shape mismatch at seq {expected_seq}"}
            elif row["kind"] == "HUMAN_DECISION_RECORDED":
                try:
                    if _sha256(_decision_identity_payload(payload)) != payload["decision_id"]:
                        return {"ok": False, "count": len(rows), "error": f"decision identity mismatch at seq {expected_seq}"}
                except (KeyError, TypeError):
                    return {"ok": False, "count": len(rows), "error": f"decision shape mismatch at seq {expected_seq}"}
            prev_hash = row["event_hash"]
        return {"ok": True, "count": len(rows), "head_hash": prev_hash}
