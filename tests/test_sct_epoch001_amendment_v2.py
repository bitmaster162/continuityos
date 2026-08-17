import json
import pytest

from sct.bench.envelope import build_standard_inputs, render_request
from sct.bench.predict import validate_probability_response
from sct.bench.score import score_distribution
from sct.bench.arena import ProspectiveArena
from sct.errors import BenchError
from sct.store.sqlite import SQLiteEvidenceStore
from sct.epoch import amendment_v2_manifest


def _inputs():
    return build_standard_inputs(scenario="A/B/C?", options=["A","B","C"], provider="p", model="m", model_version="v",
        static_profile="1234567890abcdefghij", permitted_history="abcdefghij", sct_state="abcdefghij1234567890abcdefghij",
        token_budget=1000, temperature=0.0, reasoning="fixed", frozen_at=10.0)


def test_claude_counterexample_is_visible_to_multiclass_scoring():
    b=score_distribution(["A","B","C"],{"A":.5,"B":.4,"C":.1},"C")
    c=score_distribution(["A","B","C"],{"A":.5,"B":.1,"C":.4},"C")
    assert b["multiclass_brier"] == pytest.approx(1.22)
    assert c["multiclass_brier"] == pytest.approx(.62)
    assert c["multiclass_brier"]-b["multiclass_brier"] == pytest.approx(-.60)
    assert c["log_loss"] < b["log_loss"]


def test_probability_schema_is_exact_and_no_renormalization():
    probs,pred,conf=validate_probability_response(["A","B"],{"option_probabilities":{"A":.4,"B":.6}})
    assert pred=="B" and conf==.6
    with pytest.raises(BenchError,match="sum"):
        validate_probability_response(["A","B"],{"option_probabilities":{"A":.4,"B":.5}})
    with pytest.raises(BenchError,match="keys"):
        validate_probability_response(["A","B"],{"option_probabilities":{"A":1.0}})


def test_model_visible_envelope_is_identical_except_personal_context():
    inputs=_inputs(); req={a:render_request(scenario="A/B/C?",options=["A","B","C"],frozen_input=x) for a,x in inputs.items()}
    assert len({x.envelope_sha256 for x in inputs.values()})==1
    system={r["messages"][0]["content"] for r in req.values()}; assert len(system)==1
    bodies=[json.loads(r["messages"][1]["content"]) for r in req.values()]
    for body in bodies: assert set(body)=={"scenario","options","personal_context","response_contract","constraints"}
    stripped=[]
    for body in bodies:
        body=dict(body); body["personal_context"]="X"; stripped.append(body)
    assert stripped[0]==stripped[1]==stripped[2]


def test_arena_fail_closed_voids_bad_prediction_and_blocks_reveal(tmp_path):
    store=SQLiteEvidenceStore(tmp_path/"sct.db"); arena=ProspectiveArena(store)
    arena.open_case(case_id="c1",situation="A/B/C?",options=["A","B","C"],inputs=_inputs(),
        cluster={"project_id":"p1","domain_id":"engineering","time_epoch":"2026-W34","decision_family":"architecture"},frozen_at=11)
    with pytest.raises(BenchError,match="PREDICTION_SCHEMA_VIOLATION"):
        arena.submit_prediction("c1","generic",{"option_probabilities":{"A":.5,"B":.5}},committed_at=12)
    events=[e for e in store.query() if e.payload.get("case_id")=="c1"]
    assert any(e.kind=="CASE_VOIDED" for e in events)
    assert not any(e.kind=="PREDICTION_COMMITTED" for e in events)
    with pytest.raises(BenchError): arena.reveal("c1","A",decided_at=20)


def test_reveal_requires_all_three_probability_precommits(tmp_path):
    store=SQLiteEvidenceStore(tmp_path/"sct.db"); arena=ProspectiveArena(store)
    arena.open_case(case_id="c1",situation="A/B/C?",options=["A","B","C"],inputs=_inputs(),
        cluster={"project_id":"p1","domain_id":"engineering","time_epoch":"2026-W34","decision_family":"architecture"},frozen_at=11)
    r={"option_probabilities":{"A":.4,"B":.3,"C":.3}}
    arena.submit_prediction("c1","generic",r,committed_at=12)
    with pytest.raises(BenchError,match="all three"):
        arena.reveal("c1","A",decided_at=20)


def test_amendment_is_bound_to_fresh_baseline():
    m=amendment_v2_manifest(parent_commit="60f7558c13cb15a6ebac858747629ad1147852f6",parent_tree="50e10dffed773144c4c5b16788ffad10f839bf6e")
    assert m["valid_live_n_at_amendment"]==0
    assert m["execution_authority"]=="NONE"
    assert len(m["manifest_sha256"])==64
