from __future__ import annotations

from typing import Any, Mapping, Sequence
import time

from ..canon import sha256_obj
from ..errors import BenchError
from ..store.protocol import EvidenceStore
from .envelope import BASELINES, FrozenContestantInput, assert_parity
from .predict import build_prediction, Prediction
from .score import score_distribution


class ProspectiveArena:
    """Epoch-001 V2 fail-closed prospective A/B/C arena over an EvidenceStore."""

    def __init__(self, store: EvidenceStore): self.store=store

    def _events(self, case_id: str):
        return [e for e in self.store.query() if e.payload.get("case_id")==case_id]

    def _case_event(self, case_id: str):
        return next((e for e in self._events(case_id) if e.kind=="CASE_FROZEN"),None)

    def _void(self, case_id: str, reason: str):
        if not any(e.kind=="CASE_VOIDED" for e in self._events(case_id)):
            self.store.append("CASE_VOIDED",{"case_id":case_id,"reason":reason,"execution_authority":"NONE"})
        raise BenchError(reason)

    def open_case(self, *, case_id: str, situation: str, options: Sequence[str],
                  inputs: Mapping[str,FrozenContestantInput], cluster: Mapping[str,str],
                  assistant_influence: str="NONE", frozen_at: float|None=None) -> dict[str,Any]:
        if self._case_event(case_id): raise BenchError("case already exists")
        opts=tuple(dict.fromkeys(str(x).strip() for x in options if str(x).strip()))
        if len(opts)<2: raise BenchError("at least two options required")
        if assistant_influence not in {"NONE","ADVICE_GIVEN","INCLINATION_DISCLOSED","UNKNOWN"}: raise BenchError("assistant_influence")
        required={"project_id","domain_id","time_epoch","decision_family"}
        if set(cluster)!=required or any(not isinstance(cluster[k],str) or not cluster[k].strip() for k in required):
            raise BenchError("cluster metadata must be complete before freeze")
        try: assert_parity(inputs)
        except BenchError as exc: self._void(case_id,str(exc))
        ts=float(frozen_at if frozen_at is not None else time.time())
        envelope_sha=next(iter(inputs.values())).envelope_sha256
        payload={"case_id":case_id,"situation":situation.strip(),"options":opts,"cluster":dict(cluster),
                 "cluster_key":cluster["project_id"] or "personal:"+cluster["domain_id"],
                 "assistant_influence":assistant_influence,"envelope_sha256":envelope_sha,
                 "input_snapshot_sha256":{a:inputs[a].snapshot_sha256 for a in BASELINES},
                 "frozen_at":ts,"status":"OPEN","execution_authority":"NONE","can_execute":False}
        payload["case_spec_id"]=sha256_obj(payload)
        self.store.append("CASE_FROZEN",payload,ts=ts)
        for arm in BASELINES:
            self.store.append("CONTESTANT_INPUT_FROZEN",{"case_id":case_id,"arm":arm,**inputs[arm].to_dict()},ts=ts)
        return payload

    def submit_prediction(self, case_id: str, arm: str, response: Mapping[str,Any], *, committed_at: float|None=None) -> Prediction:
        case=self._case_event(case_id)
        if case is None: raise BenchError("case not open")
        events=self._events(case_id)
        if any(e.kind in {"CASE_VOIDED","DECISION_REVEALED"} for e in events): raise BenchError("predictions closed")
        if arm not in BASELINES: raise BenchError("unknown arm")
        if any(e.kind=="PREDICTION_COMMITTED" and e.payload.get("arm")==arm for e in events): raise BenchError("arm already committed")
        try:
            pred=build_prediction(case_id=case_id,arm=arm,options=case.payload["options"],response=response,
                                  committed_at=float(committed_at if committed_at is not None else time.time()))
        except BenchError:
            self._void(case_id,"PREDICTION_SCHEMA_VIOLATION")
        self.store.append("PREDICTION_COMMITTED",pred.to_dict(),ts=pred.committed_at)
        return pred

    def reveal(self, case_id: str, actual_choice: str, *, decided_at: float|None=None):
        case=self._case_event(case_id)
        if case is None: raise BenchError("case not open")
        events=self._events(case_id)
        if any(e.kind=="CASE_VOIDED" for e in events): raise BenchError("case is void")
        if any(e.kind=="DECISION_REVEALED" for e in events): raise BenchError("already revealed")
        arms={e.payload.get("arm") for e in events if e.kind=="PREDICTION_COMMITTED"}
        if arms != set(BASELINES): raise BenchError("all three predictions must be committed before reveal")
        if actual_choice not in case.payload["options"]: raise BenchError("actual choice outside options")
        ts=float(decided_at if decided_at is not None else time.time())
        rec=self.store.append("DECISION_REVEALED",{"case_id":case_id,"actual_choice":actual_choice,"decided_at":ts,"source":"HUMAN"},ts=ts)
        return rec.payload

    def score(self, case_id: str):
        case=self._case_event(case_id); events=self._events(case_id)
        reveal=next((e for e in events if e.kind=="DECISION_REVEALED"),None)
        if case is None or reveal is None: raise BenchError("case must be revealed before score")
        if any(e.kind=="CASE_VOIDED" for e in events): raise BenchError("case is void")
        existing={e.payload.get("arm") for e in events if e.kind=="CASE_SCORED"}
        out={}
        for e in events:
            if e.kind!="PREDICTION_COMMITTED": continue
            arm=e.payload["arm"]
            result=score_distribution(case.payload["options"],e.payload["option_probabilities"],reveal.payload["actual_choice"])
            out[arm]=result
            if arm not in existing:
                self.store.append("CASE_SCORED",{"case_id":case_id,"arm":arm,**result,"scorer_version":"sct.score/v1"})
        return out
