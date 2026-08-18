import hashlib
import inspect

from sct.baseline_r13 import admitted_pool_sha256, admitted_segments, build_arm_b_profile_rag
from sct.bench.envelope import build_standard_inputs
from sct.canon import sha256_obj
from sct.r13_live_provenance import build_arm_b_live_provenance_receipt, canonical_evidence_blob
from sct.store.sqlite import SQLiteEvidenceStore


def _rows():
    return [
        {"segment_id":"p1","source_id":"raw","text":"I prefer reversible evidence-gated experiments.","observed_at":100.0,"profile_eligible":True,"admitted":True,"assistant_authored":False,"sct_only_derived":False,"authorship":"HUMAN_USER"},
        {"segment_id":"h1","source_id":"raw","text":"I compare rollback cost before deployment.","observed_at":110.0,"profile_eligible":False,"admitted":True,"assistant_authored":False,"sct_only_derived":False,"authorship":"HUMAN_USER"},
    ]


def test_provenance_receipt_binds_exact_frozen_builder_and_raw_blob(tmp_path):
    rows = _rows()
    pool = admitted_pool_sha256(admitted_segments(rows, source_cutoff=200.0))
    builder = build_arm_b_profile_rag(
        scenario="Deploy or wait?", options=("deploy", "wait"), evidence_rows=rows,
        source_cutoff=200.0, target_context_bytes=512, expected_admitted_pool_sha256=pool,
    )
    inputs = build_standard_inputs(
        scenario="Deploy or wait?", options=("deploy", "wait"), provider="m", model="m", model_version="1",
        static_profile=builder["static_profile"], permitted_history=builder["permitted_history"],
        sct_state="S" * builder["payload_bytes"], token_budget=512, temperature=0.0, reasoning="fixed", frozen_at=123.0,
    )
    blob = canonical_evidence_blob(rows)
    store = SQLiteEvidenceStore(tmp_path / "blob.sqlite")
    blob_sha = store.put_blob(blob)
    assert blob_sha == hashlib.sha256(blob).hexdigest()
    receipt = build_arm_b_live_provenance_receipt(
        case_id="CASE-001", scenario="Deploy or wait?", options=("deploy", "wait"), evidence_rows=rows,
        evidence_blob_sha256=blob_sha, source_cutoff=200.0, target_context_bytes=512,
        expected_admitted_pool_sha256=pool, builder_output=builder,
        profile_rag_snapshot_sha256=inputs["profile_rag"].snapshot_sha256,
        baseline_manifest_sha256="b" * 64,
    )
    assert receipt["profile_rag_payload_sha256"] == inputs["profile_rag"].payload_sha256
    assert receipt["profile_rag_snapshot_sha256"] == inputs["profile_rag"].snapshot_sha256
    assert receipt["builder_output_sha256"] == sha256_obj(builder)
    store.close()


def test_cli_component_output_is_exact_core_receipt_and_open_case_has_no_freeform_arm_b_files():
    import sct.r13_cli as r13_cli

    block = inspect.getsource(r13_cli._run_component)
    assert "attempt_lifecycle" not in block
    assert "finish_r13_component_attempt(store, component=component, receipt=out)" in block

    parser = r13_cli.build_parser()
    open_case = next(a for a in parser._actions if getattr(a, "dest", None) == "cmd").choices["open-case"]
    dests = {a.dest for a in open_case._actions}
    assert "static_profile_file" not in dests
    assert "permitted_history_file" not in dests
    assert {"arm_b_evidence_file", "arm_b_source_cutoff", "arm_b_expected_pool_sha256"} <= dests
