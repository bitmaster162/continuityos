
import json
from pathlib import Path
import sys

import pytest

from sct.bench.arena import ProspectiveArena
from sct.bench.envelope import build_standard_inputs
from sct.dryrun import run_void_distribution_dryrun, run_real_model_void_dryrun
from sct.epoch import amendment_v2_manifest, ensure_epoch_amended
from sct.report import epoch_score_report
from sct.runner.provider import FixtureRunner, SubprocessJsonRunner
from sct.store.sqlite import SQLiteEvidenceStore


def _inputs(project=True):
    return build_standard_inputs(
        scenario="Choose A/B/C",
        options=["A", "B", "C"],
        provider="fixture",
        model="m",
        model_version="v",
        static_profile="P" * 100,
        permitted_history="",
        sct_state="S" * 100,
        token_budget=512,
        temperature=0.0,
        reasoning="fixed",
        frozen_at=10.0,
    )


def _runner():
    return FixtureRunner(
        {
            "generic": {"option_probabilities": {"A": .4, "B": .35, "C": .25}},
            "profile_rag": {"option_probabilities": {"A": .5, "B": .3, "C": .2}},
            "sct": {"option_probabilities": {"A": .5, "B": .2, "C": .3}},
        }
    )


def test_epoch_amendment_event_is_idempotent_and_live_n_zero(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    manifest = amendment_v2_manifest(
        parent_commit="60f7558c13cb15a6ebac858747629ad1147852f6",
        parent_tree="50e10dffed773144c4c5b16788ffad10f839bf6e",
    )
    first = ensure_epoch_amended(store, manifest)
    second = ensure_epoch_amended(store, manifest)
    assert first == second
    events = list(store.query(kind="EPOCH_AMENDED"))
    assert len(events) == 1
    assert events[0].payload["valid_live_n"] == 0
    assert events[0].payload["execution_authority"] == "NONE"


def test_full_fixture_runner_flow_and_personal_cluster(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    arena = ProspectiveArena(store)
    arena.open_case(
        case_id="x",
        situation="Choose A/B/C",
        options=["A", "B", "C"],
        inputs=_inputs(),
        cluster={"project_id": "", "domain_id": "personal.tools", "time_epoch": "2026-W34", "decision_family": "subscription"},
        frozen_at=11,
    )
    arena.predict_with_runner("x", _runner())
    with pytest.raises(Exception, match="already committed"):
        arena.predict_with_runner("x", _runner())
    arena.reveal("x", "C", decided_at=20)
    scores = arena.score("x")
    assert scores["sct"]["multiclass_brier"] < scores["profile_rag"]["multiclass_brier"]
    case = next(e for e in store.query(kind="CASE_FROZEN"))
    assert case.payload["cluster_key"] == "personal:personal.tools"


def test_assistant_influence_is_fail_closed_before_case_freeze(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    arena = ProspectiveArena(store)
    with pytest.raises(Exception, match="PRIOR_ASSISTANT_RECOMMENDATION_CONTAMINATION"):
        arena.open_case(
            case_id="contaminated",
            situation="A or B?",
            options=["A", "B"],
            inputs=build_standard_inputs(
                scenario="A or B?", options=["A", "B"], provider="p", model="m", model_version="v",
                static_profile="p"*20, sct_state="s"*20, frozen_at=1,
            ),
            cluster={"project_id": "p", "domain_id": "d", "time_epoch": "t", "decision_family": "f"},
            assistant_influence="ADVICE_GIVEN",
            frozen_at=2,
        )
    assert list(store.query(kind="OPPORTUNITY_REGISTERED"))[0].payload["status"] == "EXCLUDED"
    assert len(list(store.query(kind="CASE_FROZEN"))) == 0
    assert len(list(store.query(kind="CASE_VOIDED"))) == 1


def test_inferential_score_refuses_below_n_or_k(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    report = epoch_score_report(store, inferential=True)
    assert report["inferential_refused"] is True
    assert set(report["gate"]["failures"]) == {"n<100", "K<6"}


def test_mandatory_distribution_dryrun_is_10_to_20_void_cases():
    out = run_void_distribution_dryrun(cases=12)
    assert out["cases"] == 12
    assert out["void_cases"] == 12
    assert out["valid_cases"] == 0
    assert out["store_verify_ok"] is True
    assert out["all_probability_vectors_non_degenerate"] is True
    assert out["satisfies_real_model_gate"] is False


def test_subprocess_runner_is_one_shot_json(tmp_path):
    script = tmp_path / "runner.py"
    script.write_text(
        "import json,sys\n"
        "x=json.load(sys.stdin)\n"
        "assert 'arm' not in x and 'request' not in x\n"
        "assert x == {'x': 1}\n"
        "print(json.dumps({'option_probabilities': {'A': 0.6, 'B': 0.4}, 'would_escalate': False}))\n",
        encoding="utf-8",
    )
    runner = SubprocessJsonRunner([sys.executable, "-S", str(script)])
    out = runner.predict({"x": 1}, arm="generic")
    assert out["option_probabilities"]["A"] == .6


def test_payload_parity_violation_voids_before_case_freeze(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    arena = ProspectiveArena(store)
    bad = build_standard_inputs(
        scenario="A/B",
        options=["A", "B"],
        provider="p", model="m", model_version="v",
        static_profile="p" * 20,
        sct_state="s" * 200,
        frozen_at=1,
    )
    with pytest.raises(Exception, match="PARITY_BUDGET_VIOLATION"):
        arena.open_case(
            case_id="bad-parity",
            situation="A/B",
            options=["A", "B"],
            inputs=bad,
            cluster={"project_id": "p", "domain_id": "d", "time_epoch": "t", "decision_family": "f"},
            frozen_at=2,
        )
    assert not list(store.query(kind="CASE_FROZEN"))
    assert list(store.query(kind="CASE_VOIDED"))[0].payload["reason"] == "PARITY_BUDGET_VIOLATION"


def test_opportunity_ids_are_sequential_and_never_silently_dropped(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "db.sqlite")
    arena = ProspectiveArena(store)
    for idx in range(2):
        arena.open_case(
            case_id=f"c{idx}",
            situation="Choose A/B/C",
            options=["A", "B", "C"],
            inputs=_inputs(),
            cluster={"project_id": "p", "domain_id": "d", "time_epoch": "2026-W34", "decision_family": "f"},
            frozen_at=1000 + idx,
        )
    ids = [e.payload["opportunity_id"] for e in store.query(kind="OPPORTUNITY_REGISTERED")]
    assert ids[0].endswith("-001")
    assert ids[1].endswith("-002")


def test_real_model_dryrun_transport_uses_same_frozen_request_shape(tmp_path):
    script = tmp_path / "real_runner.py"
    script.write_text(
        "import json,sys\n"
        "req=json.load(sys.stdin)\n"
        "assert 'arm' not in req and 'request' not in req\n"
        "payload=json.loads(req['messages'][1]['content'])\n"
        "opts=payload['options']\n"
        "probs={opts[0]:0.5, opts[1]:0.3, opts[2]:0.2}\n"
        "print(json.dumps({'option_probabilities': probs, 'reasons':['provider'], 'change_conditions':[], 'would_escalate':False}))\n",
        encoding="utf-8",
    )
    runner = SubprocessJsonRunner([sys.executable, "-S", str(script)])
    out = run_real_model_void_dryrun(
        runner=runner, cases=10, provider="test-provider", model="real-seam-test",
        model_version="v1", runner_command_sha256="0"*64,
    )
    assert out["cases"] == 10
    assert out["prediction_vectors"] == 30
    assert out["schema_transport_pass"] is True
    assert out["satisfies_real_model_gate"] is True
    assert out["operator_attestation_required"] is True
    assert out["valid_cases"] == 0


def test_cli_requires_explicit_assistant_influence():
    from sct.cli import build_parser
    parser = build_parser()
    base = [
        "case", "open", "--id", "c", "--situation", "A/B", "--option", "A", "--option", "B",
        "--provider", "p", "--model", "m", "--model-version", "v",
        "--static-profile-file", "p.txt", "--sct-state-file", "s.txt",
        "--domain-id", "d", "--time-epoch", "t", "--decision-family", "f",
    ]
    with pytest.raises(SystemExit):
        parser.parse_args(base)
    args = parser.parse_args(base + ["--assistant-influence", "NONE"])
    assert args.assistant_influence == "NONE"
