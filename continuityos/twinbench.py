"""Blind head-to-head evaluation for SCT personal decision models.

TwinBench freezes each contestant's input snapshot, commits every prediction before
one shared human reveal, then scores the contestants through SCT-R1. It is shadow
only: no execution, no authority, no model training.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import hashlib
import json
import math
import re
import time

from .decision_twin import (
    DecisionTwinError,
    ShadowDecisionLedger,
    TwinPrediction,
    build_human_decision,
    build_prediction,
    evaluate,
)

ARENA_SCHEMA = "continuityos.sct.twinbench-arena/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _cj(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash(value: Any) -> str:
    raw = value if isinstance(value, str) else _cj(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DecisionTwinError(f"{field} must be a non-empty string")
    return value.strip()


def _ts(value: Optional[float], field: str) -> float:
    out = time.time() if value is None else float(value)
    if not math.isfinite(out):
        raise DecisionTwinError(f"{field} must be finite")
    return out


def _digest(value: str, field: str) -> str:
    value = _text(value, field)
    if not _SHA256.fullmatch(value):
        raise DecisionTwinError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def _options(values: Sequence[str]) -> Tuple[str, ...]:
    out: List[str] = []
    for raw in values:
        item = _text(raw, "options")
        if item not in out:
            out.append(item)
    if len(out) < 2:
        raise DecisionTwinError("options must contain at least two distinct choices")
    return tuple(out)


def _case_identity(payload: Dict[str, Any]) -> Dict[str, Any]:
    keys = (
        "schema", "case_id", "situation", "options", "contestants",
        "input_snapshots", "opened_at", "mode", "execution_authority", "can_execute",
    )
    return {key: payload[key] for key in keys}


def _reveal_identity(payload: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("schema", "case_id", "actual_choice", "reasons", "decided_at", "source")
    return {key: payload[key] for key in keys}


class TwinBenchArena(ShadowDecisionLedger):
    """A dedicated append-only arena ledger layered on SCT-R1."""

    CASE_KIND = "TWINBENCH_CASE_OPENED"
    REVEAL_KIND = "TWINBENCH_HUMAN_REVEALED"

    def _case(self, case_id: str) -> Optional[Dict[str, Any]]:
        return next(
            (
                row["payload"] for row in self._rows()
                if row["kind"] == self.CASE_KIND and row["payload"].get("case_id") == case_id
            ),
            None,
        )

    def _reveal(self, case_id: str) -> Optional[Dict[str, Any]]:
        return next(
            (
                row["payload"] for row in self._rows()
                if row["kind"] == self.REVEAL_KIND and row["payload"].get("case_id") == case_id
            ),
            None,
        )

    def _predictions(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        rows = [
            row["payload"] for row in self._rows()
            if row["kind"] == "TWIN_PREDICTION_COMMITTED"
        ]
        return rows if case_id is None else [row for row in rows if row.get("case_id") == case_id]

    def _evaluations(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        rows = [
            row["payload"] for row in self._rows()
            if row["kind"] == "TWIN_EVALUATION_RECORDED"
        ]
        return rows if case_id is None else [row for row in rows if row.get("case_id") == case_id]

    def open_case(
        self,
        *,
        case_id: str,
        situation: str,
        options: Sequence[str],
        input_snapshots: Mapping[str, str],
        opened_at: Optional[float] = None,
    ) -> Dict[str, Any]:
        case_id = _text(case_id, "case_id")
        if self._case(case_id):
            raise DecisionTwinError("case_id is already open")
        if not isinstance(input_snapshots, Mapping) or len(input_snapshots) < 2:
            raise DecisionTwinError("input_snapshots must define at least two contestants")
        snapshots: Dict[str, str] = {}
        for raw_name, raw_sha in input_snapshots.items():
            name = _text(raw_name, "contestant_id")
            snapshots[name] = _digest(raw_sha, f"input_snapshots[{name}]")
        payload = {
            "schema": ARENA_SCHEMA,
            "case_id": case_id,
            "situation": _text(situation, "situation"),
            "options": _options(options),
            "contestants": tuple(snapshots),
            "input_snapshots": snapshots,
            "opened_at": _ts(opened_at, "opened_at"),
            "mode": "SHADOW",
            "execution_authority": "NONE",
            "can_execute": False,
        }
        payload["case_spec_id"] = _hash(_case_identity(payload))
        self.append(self.CASE_KIND, payload, ts=payload["opened_at"])
        return payload

    def submit_prediction(
        self,
        case_id: str,
        contestant_id: str,
        *,
        predicted_choice: str,
        confidence: float,
        reasons: Optional[Iterable[str]] = None,
        evidence_refs: Optional[Iterable[str]] = None,
        change_conditions: Optional[Iterable[str]] = None,
        would_escalate: bool = False,
        created_at: Optional[float] = None,
    ) -> TwinPrediction:
        case_id = _text(case_id, "case_id")
        case = self._case(case_id)
        if case is None:
            raise DecisionTwinError("case must be opened before predictions")
        if self._reveal(case_id):
            raise DecisionTwinError("predictions are closed after the human reveal")
        contestant_id = _text(contestant_id, "contestant_id")
        if contestant_id not in case["contestants"]:
            raise DecisionTwinError("contestant is not registered for this case")
        if any(row.get("model_id") == contestant_id for row in self._predictions(case_id)):
            raise DecisionTwinError("contestant already committed a prediction for this case")
        created_at = _ts(created_at, "created_at")
        if created_at < float(case["opened_at"]):
            raise DecisionTwinError("prediction cannot predate arena case opening")
        prediction = build_prediction(
            case_id=case_id,
            situation=case["situation"],
            options=case["options"],
            predicted_choice=predicted_choice,
            confidence=confidence,
            reasons=reasons,
            evidence_refs=evidence_refs,
            change_conditions=change_conditions,
            would_escalate=would_escalate,
            twin_snapshot_id=case["input_snapshots"][contestant_id],
            model_id=contestant_id,
            created_at=created_at,
        )
        self.commit_prediction(prediction)
        return prediction

    def reveal_human(
        self,
        case_id: str,
        *,
        actual_choice: str,
        reasons: Optional[Iterable[str]] = None,
        decided_at: Optional[float] = None,
    ) -> Dict[str, Any]:
        case_id = _text(case_id, "case_id")
        case = self._case(case_id)
        if case is None:
            raise DecisionTwinError("case does not exist")
        if self._reveal(case_id):
            raise DecisionTwinError("human outcome is already revealed")
        predictions = self._predictions(case_id)
        committed = {row.get("model_id") for row in predictions}
        expected = set(case["contestants"])
        if committed != expected:
            raise DecisionTwinError(
                f"all contestants must commit before reveal; missing={sorted(expected - committed)}"
            )
        actual_choice = _text(actual_choice, "actual_choice")
        if actual_choice not in case["options"]:
            raise DecisionTwinError("actual_choice must be one of case options")
        decided_at = _ts(decided_at, "decided_at")
        if decided_at < max(float(row["created_at"]) for row in predictions):
            raise DecisionTwinError("human reveal cannot predate committed predictions")
        payload = {
            "schema": ARENA_SCHEMA,
            "case_id": case_id,
            "actual_choice": actual_choice,
            "reasons": tuple(_text(value, "reasons") for value in (reasons or ())),
            "decided_at": decided_at,
            "source": "HUMAN",
        }
        payload["reveal_id"] = _hash(_reveal_identity(payload))
        self.append(self.REVEAL_KIND, payload, ts=decided_at)
        return payload

    @staticmethod
    def _prediction(payload: Dict[str, Any]) -> TwinPrediction:
        keys = (
            "case_id", "situation", "options", "predicted_choice", "confidence",
            "reasons", "evidence_refs", "change_conditions", "would_escalate",
            "twin_snapshot_id", "model_id", "created_at", "prediction_id",
            "schema", "mode", "execution_authority", "can_execute",
        )
        return TwinPrediction(**{key: payload[key] for key in keys})

    def finalize_case(self, case_id: str, *, evaluated_at: Optional[float] = None) -> Dict[str, Any]:
        case_id = _text(case_id, "case_id")
        reveal = self._reveal(case_id)
        if reveal is None:
            raise DecisionTwinError("human outcome must be revealed before evaluation")
        existing = {row["prediction_id"] for row in self._evaluations(case_id)}
        evaluated_at = _ts(evaluated_at, "evaluated_at")
        if evaluated_at < float(reveal["decided_at"]):
            raise DecisionTwinError("evaluation cannot predate human reveal")
        for payload in self._predictions(case_id):
            if payload["prediction_id"] in existing:
                continue
            prediction = self._prediction(payload)
            decision = build_human_decision(
                prediction,
                actual_choice=reveal["actual_choice"],
                reasons=reveal.get("reasons") or (),
                decided_at=reveal["decided_at"],
            )
            self.record_human_decision(decision)
            self.record_evaluation(evaluate(prediction, decision, evaluated_at=evaluated_at))
        return self.case_scorecard(case_id)

    def case_scorecard(self, case_id: str) -> Dict[str, Any]:
        predictions = {row["prediction_id"]: row for row in self._predictions(case_id)}
        scores = []
        for result in self._evaluations(case_id):
            prediction = predictions.get(result["prediction_id"])
            if prediction:
                scores.append({
                    "contestant_id": prediction.get("model_id"),
                    "prediction_id": result["prediction_id"],
                    "predicted_choice": prediction["predicted_choice"],
                    "correct": bool(result["correct"]),
                    "confidence": float(result["confidence"]),
                    "absolute_calibration_error": float(result["absolute_calibration_error"]),
                    "brier": float(result["squared_calibration_error"]),
                    "escalated": bool(result["escalated"]),
                })
        scores.sort(key=lambda row: row["contestant_id"] or "")
        reveal = self._reveal(case_id)
        return {
            "schema": ARENA_SCHEMA,
            "case_id": case_id,
            "actual_choice": None if reveal is None else reveal["actual_choice"],
            "scores": scores,
            "complete": bool(reveal) and len(scores) == len(predictions),
        }

    def leaderboard(self, *, min_cases: int = 10) -> Dict[str, Any]:
        if isinstance(min_cases, bool) or not isinstance(min_cases, int) or min_cases < 1:
            raise DecisionTwinError("min_cases must be a positive integer")
        predictions = {row["prediction_id"]: row for row in self._predictions()}
        buckets: Dict[str, List[Dict[str, Any]]] = {}
        case_sets: Dict[str, set[str]] = {}
        for result in self._evaluations():
            prediction = predictions.get(result["prediction_id"])
            contestant = None if prediction is None else prediction.get("model_id")
            if not contestant:
                continue
            buckets.setdefault(contestant, []).append(result)
            case_sets.setdefault(contestant, set()).add(result["case_id"])
        rows = []
        for contestant, values in sorted(buckets.items()):
            n = len(values)
            rows.append({
                "contestant_id": contestant,
                "cases": n,
                "eligible": n >= min_cases,
                "accuracy": sum(bool(v["correct"]) for v in values) / n,
                "mean_confidence": sum(float(v["confidence"]) for v in values) / n,
                "mean_absolute_calibration_error": sum(float(v["absolute_calibration_error"]) for v in values) / n,
                "mean_brier": sum(float(v["squared_calibration_error"]) for v in values) / n,
                "escalation_rate": sum(bool(v["escalated"]) for v in values) / n,
            })
        eligible = [row for row in rows if row["eligible"]]
        coverage = [frozenset(case_sets[row["contestant_id"]]) for row in eligible]
        aligned = len(set(coverage)) <= 1
        ranking = (
            sorted(eligible, key=lambda row: (-row["accuracy"], row["mean_brier"], row["contestant_id"]))
            if aligned else []
        )
        return {
            "schema": ARENA_SCHEMA,
            "min_cases": min_cases,
            "contestants": rows,
            "coverage_aligned": aligned,
            "ranking": [row["contestant_id"] for row in ranking],
            "winner": ranking[0]["contestant_id"] if len(ranking) >= 2 else None,
            "winner_is_provisional": bool(ranking),
        }

    def pairwise(self, contestant_a: str, contestant_b: str) -> Dict[str, Any]:
        a, b = _text(contestant_a, "contestant_a"), _text(contestant_b, "contestant_b")
        if a == b:
            raise DecisionTwinError("pairwise contestants must differ")
        predictions = {row["prediction_id"]: row for row in self._predictions()}
        by_case: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for result in self._evaluations():
            prediction = predictions.get(result["prediction_id"])
            contestant = None if prediction is None else prediction.get("model_id")
            if contestant in (a, b):
                by_case.setdefault(result["case_id"], {})[contestant] = result
        common = [case for case, values in by_case.items() if a in values and b in values]
        a_only = b_only = both_correct = both_wrong = 0
        a_brier = b_brier = 0.0
        for case in common:
            av, bv = by_case[case][a], by_case[case][b]
            ac, bc = bool(av["correct"]), bool(bv["correct"])
            if ac and bc:
                both_correct += 1
            elif ac:
                a_only += 1
            elif bc:
                b_only += 1
            else:
                both_wrong += 1
            a_brier += float(av["squared_calibration_error"])
            b_brier += float(bv["squared_calibration_error"])
        n = len(common)
        return {
            "schema": ARENA_SCHEMA,
            "contestant_a": a,
            "contestant_b": b,
            "common_cases": n,
            "a_only_correct": a_only,
            "b_only_correct": b_only,
            "both_correct": both_correct,
            "both_wrong": both_wrong,
            "accuracy_delta_a_minus_b": None if not n else (a_only - b_only) / n,
            "mean_brier_a": None if not n else a_brier / n,
            "mean_brier_b": None if not n else b_brier / n,
        }

    def verify(self) -> Dict[str, Any]:
        base = super().verify()
        if not base.get("ok"):
            return base
        cases: Dict[str, Dict[str, Any]] = {}
        predictions: Dict[str, Dict[str, Dict[str, Any]]] = {}
        reveals: set[str] = set()
        for row in self._rows():
            payload = row["payload"]
            if row["kind"] == self.CASE_KIND:
                case_id = payload.get("case_id")
                if case_id in cases:
                    return {"ok": False, "count": base["count"], "error": f"duplicate arena case {case_id}"}
                try:
                    if _hash(_case_identity(payload)) != payload["case_spec_id"]:
                        raise KeyError
                    for contestant in payload["contestants"]:
                        _digest(payload["input_snapshots"][contestant], "input_snapshot")
                except (KeyError, TypeError, DecisionTwinError):
                    return {"ok": False, "count": base["count"], "error": f"invalid arena case {case_id}"}
                cases[case_id], predictions[case_id] = payload, {}
            elif row["kind"] == "TWIN_PREDICTION_COMMITTED":
                case_id, contestant = payload.get("case_id"), payload.get("model_id")
                if case_id not in cases:
                    return {"ok": False, "count": base["count"], "error": f"prediction before arena case {case_id}"}
                if contestant not in cases[case_id]["contestants"] or contestant in predictions[case_id]:
                    return {"ok": False, "count": base["count"], "error": f"invalid contestant {contestant}"}
                if case_id in reveals:
                    return {"ok": False, "count": base["count"], "error": f"prediction after reveal {case_id}"}
                if payload.get("twin_snapshot_id") != cases[case_id]["input_snapshots"][contestant]:
                    return {"ok": False, "count": base["count"], "error": f"input snapshot mismatch {contestant}"}
                predictions[case_id][contestant] = payload
            elif row["kind"] == self.REVEAL_KIND:
                case_id = payload.get("case_id")
                if case_id not in cases or case_id in reveals:
                    return {"ok": False, "count": base["count"], "error": f"invalid reveal {case_id}"}
                if set(predictions[case_id]) != set(cases[case_id]["contestants"]):
                    return {"ok": False, "count": base["count"], "error": f"premature reveal {case_id}"}
                try:
                    if _hash(_reveal_identity(payload)) != payload["reveal_id"]:
                        raise KeyError
                except (KeyError, TypeError):
                    return {"ok": False, "count": base["count"], "error": f"reveal identity mismatch {case_id}"}
                reveals.add(case_id)
        return {
            "ok": True,
            "count": base["count"],
            "head_hash": base.get("head_hash"),
            "arena_cases": len(cases),
            "revealed_cases": len(reveals),
        }
