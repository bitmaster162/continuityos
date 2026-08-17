
from __future__ import annotations

from dataclasses import fields
from typing import Any, Mapping, Sequence
from datetime import datetime, timezone
import time

from ..canon import sha256_obj
from ..errors import BenchError
from ..store.protocol import EvidenceStore
from .envelope import BASELINES, FrozenContestantInput, assert_parity, render_request
from .predict import build_prediction, Prediction
from .score import SCORER_VERSION, score_distribution


class ProspectiveArena:
    """Epoch-001 V2 fail-closed prospective A/B/C arena over an EvidenceStore."""

    def __init__(self, store: EvidenceStore):
        self.store = store


    def _next_opportunity_id(self, ts: float) -> str:
        day = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d")
        prefix = f"OPP-{day}-"
        existing = [
            str(e.payload.get("opportunity_id", ""))
            for e in self.store.query(kind="OPPORTUNITY_REGISTERED")
            if str(e.payload.get("opportunity_id", "")).startswith(prefix)
        ]
        serials = []
        for value in existing:
            try:
                serials.append(int(value.rsplit("-", 1)[1]))
            except (ValueError, IndexError):
                continue
        return f"{prefix}{(max(serials, default=0) + 1):03d}"

    def _events(self, case_id: str):
        return [e for e in self.store.query() if e.payload.get("case_id") == case_id]

    def _case_event(self, case_id: str):
        return next((e for e in self._events(case_id) if e.kind == "CASE_FROZEN"), None)

    def _void(self, case_id: str, reason: str):
        if not any(e.kind == "CASE_VOIDED" for e in self._events(case_id)):
            self.store.append(
                "CASE_VOIDED",
                {"case_id": case_id, "reason": reason, "execution_authority": "NONE"},
            )
        raise BenchError(reason)

    def void_case(self, case_id: str, reason: str) -> None:
        """Explicitly mark a completed synthetic/debug case VOID."""
        if self._case_event(case_id) is None:
            raise BenchError("case not open")
        if not any(e.kind == "CASE_VOIDED" for e in self._events(case_id)):
            self.store.append(
                "CASE_VOIDED",
                {"case_id": case_id, "reason": reason, "execution_authority": "NONE"},
            )

    def open_case(
        self,
        *,
        case_id: str,
        situation: str,
        options: Sequence[str],
        inputs: Mapping[str, FrozenContestantInput],
        cluster: Mapping[str, str],
        assistant_influence: str = "NONE",
        frozen_at: float | None = None,
    ) -> dict[str, Any]:
        if self._case_event(case_id):
            raise BenchError("case already exists")
        opts = tuple(dict.fromkeys(str(x).strip() for x in options if str(x).strip()))
        if len(opts) < 2:
            raise BenchError("at least two options required")
        if assistant_influence not in {"NONE", "ADVICE_GIVEN", "INCLINATION_DISCLOSED", "UNKNOWN"}:
            raise BenchError("assistant_influence")
        required = {"project_id", "domain_id", "time_epoch", "decision_family"}
        if set(cluster) != required:
            raise BenchError("cluster metadata must be complete before freeze")
        if not isinstance(cluster["project_id"], str):
            raise BenchError("project_id must be a string (empty means personal/non-project)")
        for key in ("domain_id", "time_epoch", "decision_family"):
            if not isinstance(cluster[key], str) or not cluster[key].strip():
                raise BenchError(f"{key} must be non-empty before freeze")

        ts = float(frozen_at if frozen_at is not None else time.time())
        cluster_clean = {k: str(v).strip() for k, v in cluster.items()}
        cluster_key = cluster_clean["project_id"] or "personal:" + cluster_clean["domain_id"]

        # R26-style observed opportunity event precedes case finalization.
        self.store.append(
            "OPPORTUNITY_REGISTERED",
            {
                "case_id": case_id,
                "opportunity_id": self._next_opportunity_id(ts),
                "registered_at": ts,
                "status": "ENROLLED" if assistant_influence == "NONE" else "EXCLUDED",
                "assistant_influence": assistant_influence,
                "cluster": cluster_clean,
                "cluster_key": cluster_key,
                "inference_scope": "SCT_PRESENTED_DECISIONS_ONLY",
                "execution_authority": "NONE",
            },
            ts=ts,
        )

        if assistant_influence != "NONE":
            self._void(
                case_id,
                "PRIOR_ASSISTANT_RECOMMENDATION_CONTAMINATION"
                if assistant_influence == "ADVICE_GIVEN"
                else "HUMAN_INCLINATION_LEAKAGE"
                if assistant_influence == "INCLINATION_DISCLOSED"
                else "ASSISTANT_INFLUENCE_UNKNOWN",
            )

        try:
            assert_parity(inputs)
        except BenchError as exc:
            self._void(case_id, str(exc))

        envelope_sha = next(iter(inputs.values())).envelope_sha256
        payload = {
            "case_id": case_id,
            "situation": situation.strip(),
            "options": opts,
            "cluster": cluster_clean,
            "cluster_key": cluster_key,
            "assistant_influence": assistant_influence,
            "envelope_sha256": envelope_sha,
            "input_snapshot_sha256": {a: inputs[a].snapshot_sha256 for a in BASELINES},
            "frozen_at": ts,
            "status": "OPEN",
            "execution_authority": "NONE",
            "can_execute": False,
        }
        payload["case_spec_id"] = sha256_obj(payload)
        self.store.append("CASE_FROZEN", payload, ts=ts)
        for arm in BASELINES:
            self.store.append(
                "CONTESTANT_INPUT_FROZEN",
                {"case_id": case_id, "arm": arm, **inputs[arm].to_dict()},
                ts=ts,
            )
        return payload

    def frozen_inputs(self, case_id: str) -> dict[str, FrozenContestantInput]:
        case = self._case_event(case_id)
        if case is None:
            raise BenchError("case not open")
        allowed = {f.name for f in fields(FrozenContestantInput)}
        out: dict[str, FrozenContestantInput] = {}
        for e in self._events(case_id):
            if e.kind != "CONTESTANT_INPUT_FROZEN":
                continue
            arm = str(e.payload["arm"])
            kwargs = {k: e.payload[k] for k in allowed if k in e.payload}
            out[arm] = FrozenContestantInput(**kwargs)
        if set(out) != set(BASELINES):
            raise BenchError("frozen A/B/C inputs incomplete")
        return out

    def requests(self, case_id: str) -> dict[str, dict[str, Any]]:
        case = self._case_event(case_id)
        if case is None:
            raise BenchError("case not open")
        inputs = self.frozen_inputs(case_id)
        return {
            arm: render_request(
                scenario=case.payload["situation"],
                options=case.payload["options"],
                frozen_input=inputs[arm],
            )
            for arm in BASELINES
        }

    def submit_prediction(
        self,
        case_id: str,
        arm: str,
        response: Mapping[str, Any],
        *,
        committed_at: float | None = None,
    ) -> Prediction:
        case = self._case_event(case_id)
        if case is None:
            raise BenchError("case not open")
        events = self._events(case_id)
        if any(e.kind in {"CASE_VOIDED", "DECISION_REVEALED"} for e in events):
            raise BenchError("predictions closed")
        if arm not in BASELINES:
            raise BenchError("unknown arm")
        if any(e.kind == "PREDICTION_COMMITTED" and e.payload.get("arm") == arm for e in events):
            raise BenchError("arm already committed")
        try:
            pred = build_prediction(
                case_id=case_id,
                arm=arm,
                options=case.payload["options"],
                response=response,
                committed_at=float(committed_at if committed_at is not None else time.time()),
            )
        except BenchError:
            self._void(case_id, "PREDICTION_SCHEMA_VIOLATION")
        self.store.append("PREDICTION_COMMITTED", pred.to_dict(), ts=pred.committed_at)
        return pred

    def predict_with_runner(self, case_id: str, runner) -> dict[str, Prediction]:
        """Run A/B/C exactly once each. Any runner/schema failure voids the whole case."""
        requests = self.requests(case_id)
        out: dict[str, Prediction] = {}
        for arm in BASELINES:
            try:
                response = runner.predict(requests[arm], arm=arm)
            except Exception as exc:
                self._void(case_id, f"PROVIDER_RUNNER_FAILURE:{type(exc).__name__}")
            out[arm] = self.submit_prediction(case_id, arm, response)
        return out

    def reveal(self, case_id: str, actual_choice: str, *, decided_at: float | None = None):
        case = self._case_event(case_id)
        if case is None:
            raise BenchError("case not open")
        events = self._events(case_id)
        if any(e.kind == "CASE_VOIDED" for e in events):
            raise BenchError("case is void")
        if any(e.kind == "DECISION_REVEALED" for e in events):
            raise BenchError("already revealed")
        arms = {e.payload.get("arm") for e in events if e.kind == "PREDICTION_COMMITTED"}
        if arms != set(BASELINES):
            raise BenchError("all three predictions must be committed before reveal")
        if actual_choice not in case.payload["options"]:
            raise BenchError("actual choice outside options")
        ts = float(decided_at if decided_at is not None else time.time())
        rec = self.store.append(
            "DECISION_REVEALED",
            {"case_id": case_id, "actual_choice": actual_choice, "decided_at": ts, "source": "HUMAN"},
            ts=ts,
        )
        return rec.payload

    def score(self, case_id: str):
        case = self._case_event(case_id)
        events = self._events(case_id)
        reveal = next((e for e in events if e.kind == "DECISION_REVEALED"), None)
        if case is None or reveal is None:
            raise BenchError("case must be revealed before score")
        if any(e.kind == "CASE_VOIDED" for e in events):
            raise BenchError("case is void")
        existing = {e.payload.get("arm") for e in events if e.kind == "CASE_SCORED"}
        out = {}
        for e in events:
            if e.kind != "PREDICTION_COMMITTED":
                continue
            arm = e.payload["arm"]
            result = score_distribution(
                case.payload["options"],
                e.payload["option_probabilities"],
                reveal.payload["actual_choice"],
            )
            out[arm] = result
            if arm not in existing:
                self.store.append(
                    "CASE_SCORED",
                    {
                        "case_id": case_id,
                        "arm": arm,
                        "cluster_key": case.payload["cluster_key"],
                        **result,
                        "scorer_version": SCORER_VERSION,
                    },
                )
        return out
