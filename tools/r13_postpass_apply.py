from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one patch target, got {count}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# Component receipt emitted by CLI must be the same core receipt hash-bound in EvidenceStore.
replace_once(
    "sct/r13_cli.py",
    '''        lifecycle = finish_r13_component_attempt(store, component=component, receipt=out)\n        return _emit(\n            {**out, "attempt_lifecycle": lifecycle},\n            0 if out.get(pass_field) is True else 2,\n        )''',
    '''        finish_r13_component_attempt(store, component=component, receipt=out)\n        return _emit(\n            out,\n            0 if out.get(pass_field) is True else 2,\n        )''',
)

# LIVE open-case must construct Arm B from frozen builder inputs, not caller-supplied profile text.
replace_once(
    "sct/r13_cli.py",
    "from .bench.envelope import BASELINES, build_standard_inputs\n",
    "from .bench.envelope import BASELINES, build_standard_inputs\nfrom .baseline_r13 import build_arm_b_profile_rag\n",
)
replace_once(
    "sct/r13_cli.py",
    "from .r13_manifest_guard import validate_baseline_for_seal, validate_model_manifest_for_seal\n",
    "from .r13_manifest_guard import validate_baseline_for_seal, validate_model_manifest_for_seal\nfrom .r13_live_provenance import build_arm_b_live_provenance_receipt, canonical_evidence_blob\n",
)
replace_once(
    "sct/r13_cli.py",
    '''def _json_file(path: str) -> dict:\n    value = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))\n    if not isinstance(value, dict):\n        raise SctError(f"JSON object required: {path}")\n    return value\n\n\n''',
    '''def _json_file(path: str) -> dict:\n    value = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))\n    if not isinstance(value, dict):\n        raise SctError(f"JSON object required: {path}")\n    return value\n\n\ndef _json_array_file(path: str) -> list[dict]:\n    value = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))\n    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):\n        raise SctError(f"JSON array of objects required: {path}")\n    return value\n\n\n''',
)
replace_once(
    "sct/r13_cli.py",
    '''    op.add_argument("--static-profile-file", required=True)\n    op.add_argument("--permitted-history-file")\n    op.add_argument("--sct-state-file", required=True)''',
    '''    op.add_argument("--arm-b-evidence-file", required=True)\n    op.add_argument("--arm-b-source-cutoff", type=float, required=True)\n    op.add_argument("--arm-b-expected-pool-sha256", required=True)\n    op.add_argument("--sct-state-file", required=True)''',
)
replace_once(
    "sct/r13_cli.py",
    '''            inputs = build_standard_inputs(\n                scenario=args.situation,\n                options=args.option,\n                provider=model_id,\n                model=model_id,\n                model_version=model_version,\n                static_profile=_read_text(args.static_profile_file),\n                permitted_history=_read_text(args.permitted_history_file),\n                sct_state=_read_text(args.sct_state_file),\n                token_budget=args.token_budget,\n                temperature=args.temperature,\n                reasoning=args.reasoning,\n                frozen_at=__import__("time").time(),\n            )\n            arena = ProspectiveArena(store)''',
    '''            evidence_rows = _json_array_file(args.arm_b_evidence_file)\n            sct_state = _read_text(args.sct_state_file)\n            target_context_bytes = len(sct_state.encode("utf-8"))\n            builder_output = build_arm_b_profile_rag(\n                scenario=args.situation,\n                options=args.option,\n                evidence_rows=evidence_rows,\n                source_cutoff=args.arm_b_source_cutoff,\n                target_context_bytes=target_context_bytes,\n                expected_admitted_pool_sha256=args.arm_b_expected_pool_sha256,\n            )\n            frozen_at = __import__("time").time()\n            inputs = build_standard_inputs(\n                scenario=args.situation,\n                options=args.option,\n                provider=model_id,\n                model=model_id,\n                model_version=model_version,\n                static_profile=builder_output["static_profile"],\n                permitted_history=builder_output["permitted_history"],\n                sct_state=sct_state,\n                token_budget=args.token_budget,\n                temperature=args.temperature,\n                reasoning=args.reasoning,\n                frozen_at=frozen_at,\n            )\n            baseline_events = list(store.query(kind="R13_BASELINE_SPEC_SEALED"))\n            if not baseline_events:\n                raise SctError("R13 Arm B baseline must be sealed before LIVE provenance")\n            evidence_blob_sha256 = store.put_blob(canonical_evidence_blob(evidence_rows))\n            arm_b_provenance = build_arm_b_live_provenance_receipt(\n                case_id=args.id,\n                scenario=args.situation,\n                options=args.option,\n                evidence_rows=evidence_rows,\n                evidence_blob_sha256=evidence_blob_sha256,\n                source_cutoff=args.arm_b_source_cutoff,\n                target_context_bytes=target_context_bytes,\n                expected_admitted_pool_sha256=args.arm_b_expected_pool_sha256,\n                builder_output=builder_output,\n                profile_rag_snapshot_sha256=inputs["profile_rag"].snapshot_sha256,\n                baseline_manifest_sha256=baseline_events[-1].payload["baseline_manifest_sha256"],\n            )\n            store.append("R13_ARM_B_LIVE_PROVENANCE_VERIFIED", arm_b_provenance)\n            arena = ProspectiveArena(store)''',
)
replace_once(
    "sct/r13_cli.py",
    '''                assistant_influence=args.assistant_influence,\n            )\n            mapping = freeze_case_mapping(''',
    '''                assistant_influence=args.assistant_influence,\n                frozen_at=frozen_at,\n            )\n            mapping = freeze_case_mapping(''',
)
replace_once(
    "sct/r13_cli.py",
    '''                    "mapping": mapping,\n                    "request_hashes": {arm: sha256_obj(requests[arm]) for arm in BASELINES},''',
    '''                    "mapping": mapping,\n                    "arm_b_provenance": arm_b_provenance,\n                    "request_hashes": {arm: sha256_obj(requests[arm]) for arm in BASELINES},''',
)

# Store-level gates protect direct Python/store bypasses as well as CLI.
sqlite_path = Path("sct/store/sqlite.py")
sqlite = sqlite_path.read_text(encoding="utf-8")
append_marker = '''    def append(self, kind: str, payload: Mapping[str, Any], *, ts: Optional[float] = None) -> EventRecord:\n'''
if sqlite.count(append_marker) != 1:
    raise SystemExit("sct/store/sqlite.py: append marker mismatch")
methods = r'''    def _r13_is_active(self) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM event WHERE kind='R13_PRECASE_PROTOCOL_AMENDED' ORDER BY seq DESC LIMIT 1"
        ).fetchone() is not None

    def _require_r13_arm_b_live_provenance_append(self, payload: Mapping[str, Any]) -> None:
        if not self._r13_is_active():
            return
        case_id = payload.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise EvidenceError("R13_ARM_B_LIVE_PROVENANCE_BLOCKED: case_id required")
        if self._conn.execute(
            "SELECT 1 FROM event WHERE kind='CASE_FROZEN' AND json_extract(payload,'$.case_id')=? LIMIT 1",
            (case_id,),
        ).fetchone() is not None:
            raise EvidenceError("R13_ARM_B_LIVE_PROVENANCE_BLOCKED: provenance must precede CASE_FROZEN")
        if self._conn.execute(
            "SELECT 1 FROM event WHERE kind='R13_ARM_B_LIVE_PROVENANCE_VERIFIED' "
            "AND json_extract(payload,'$.case_id')=? LIMIT 1",
            (case_id,),
        ).fetchone() is not None:
            raise EvidenceError("R13_ARM_B_LIVE_PROVENANCE_BLOCKED: duplicate case provenance")
        baseline = self._conn.execute(
            "SELECT payload FROM event WHERE kind='R13_BASELINE_SPEC_SEALED' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if baseline is None:
            raise EvidenceError("R13_ARM_B_LIVE_PROVENANCE_BLOCKED: sealed baseline required")
        blob_sha = payload.get("evidence_blob_sha256")
        if not isinstance(blob_sha, str):
            raise EvidenceError("R13_ARM_B_LIVE_PROVENANCE_BLOCKED: evidence blob required")
        from ..r13_live_provenance import validate_arm_b_live_provenance_receipt
        validated = validate_arm_b_live_provenance_receipt(
            payload,
            evidence_blob=self.get_blob(blob_sha),
            sealed_baseline=json.loads(baseline["payload"]),
        )
        if canonical_json(validated) != canonical_json(dict(payload)):
            raise EvidenceError("R13_ARM_B_LIVE_PROVENANCE_BLOCKED: non-canonical provenance receipt")

    def _require_r13_case_arm_b_binding_if_active(self, payload: Mapping[str, Any]) -> None:
        if not self._r13_is_active():
            return
        case_id = payload.get("case_id")
        row = self._conn.execute(
            "SELECT payload FROM event WHERE kind='R13_ARM_B_LIVE_PROVENANCE_VERIFIED' "
            "AND json_extract(payload,'$.case_id')=? ORDER BY seq DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        if row is None:
            raise EvidenceError("R13_ARM_B_LIVE_PROVENANCE_REQUIRED: verified builder receipt required before CASE_FROZEN")
        provenance = json.loads(row["payload"])
        snapshots = payload.get("input_snapshot_sha256")
        baseline = self._conn.execute(
            "SELECT payload FROM event WHERE kind='R13_BASELINE_SPEC_SEALED' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        baseline_payload = json.loads(baseline["payload"]) if baseline is not None else {}
        if (
            not isinstance(snapshots, Mapping)
            or snapshots.get("profile_rag") != provenance.get("profile_rag_snapshot_sha256")
            or provenance.get("baseline_manifest_sha256") != baseline_payload.get("baseline_manifest_sha256")
            or provenance.get("scenario") != payload.get("situation")
            or tuple(provenance.get("options") or ()) != tuple(payload.get("options") or ())
        ):
            raise EvidenceError("R13_ARM_B_LIVE_PROVENANCE_MISMATCH: CASE_FROZEN not bound to verified Arm B builder output")

    def _require_r13_profile_rag_input_binding_if_active(self, payload: Mapping[str, Any]) -> None:
        if not self._r13_is_active() or payload.get("arm") != "profile_rag":
            return
        case_id = payload.get("case_id")
        row = self._conn.execute(
            "SELECT payload FROM event WHERE kind='R13_ARM_B_LIVE_PROVENANCE_VERIFIED' "
            "AND json_extract(payload,'$.case_id')=? ORDER BY seq DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        if row is None:
            raise EvidenceError("R13_ARM_B_LIVE_PROVENANCE_REQUIRED: profile_rag provenance missing")
        provenance = json.loads(row["payload"])
        builder = provenance.get("builder_output") or {}
        expected_context = str(builder.get("static_profile") or "") + "\n" + str(builder.get("permitted_history") or "")
        if (
            payload.get("snapshot_sha256") != provenance.get("profile_rag_snapshot_sha256")
            or payload.get("payload_sha256") != provenance.get("profile_rag_payload_sha256")
            or payload.get("personal_context") != expected_context
            or sha256_obj(payload.get("personal_context")) != provenance.get("profile_rag_payload_sha256")
            or payload.get("execution_authority") != "NONE"
            or payload.get("can_execute") is not False
        ):
            raise EvidenceError("R13_ARM_B_LIVE_PROVENANCE_MISMATCH: frozen profile_rag input differs from verified builder output")

'''
sqlite = sqlite.replace(append_marker, methods + append_marker, 1)
old_dispatch = '''            if clean_kind == "CASE001_ENROLLMENT_AUTHORIZED":\n                self._require_r13_owner_authorization_append(payload_obj)\n            if clean_kind == "CASE_FROZEN":\n                self._require_r13_case_open_admission_if_active()\n'''
if sqlite.count(old_dispatch) != 1:
    raise SystemExit("sct/store/sqlite.py: append dispatch target mismatch")
new_dispatch = '''            if clean_kind == "CASE001_ENROLLMENT_AUTHORIZED":\n                self._require_r13_owner_authorization_append(payload_obj)\n            if clean_kind == "R13_ARM_B_LIVE_PROVENANCE_VERIFIED":\n                self._require_r13_arm_b_live_provenance_append(payload_obj)\n            if clean_kind == "CASE_FROZEN":\n                self._require_r13_case_open_admission_if_active()\n                self._require_r13_case_arm_b_binding_if_active(payload_obj)\n            if clean_kind == "CONTESTANT_INPUT_FROZEN":\n                self._require_r13_profile_rag_input_binding_if_active(payload_obj)\n'''
sqlite_path.write_text(sqlite.replace(old_dispatch, new_dispatch, 1), encoding="utf-8")

# Existing direct-store bypass must remain blocked after authorization unless provenance exists.
replace_once(
    "tests/test_sct_r13_live_wiring.py",
    '''    store, _, _ = _fully_authorized_store(tmp_path)\n    rec = store.append("CASE_FROZEN", {"case_id": "AUTHORIZED-DIRECT"})\n    assert rec.payload["case_id"] == "AUTHORIZED-DIRECT"\n    store.close()''',
    '''    store, _, _ = _fully_authorized_store(tmp_path)\n    with pytest.raises(EvidenceError, match="R13_ARM_B_LIVE_PROVENANCE_REQUIRED"):\n        store.append("CASE_FROZEN", {"case_id": "AUTHORIZED-DIRECT"})\n    assert not list(store.query(kind="CASE_FROZEN"))\n    store.close()''',
)

# Make the live-wiring baseline use the real frozen builder policy hashes so positive provenance can be verified.
replace_once(
    "tests/test_sct_r13_live_wiring.py",
    "from sct.bench.arena import ProspectiveArena\n",
    "from sct.bench.arena import ProspectiveArena\nfrom sct.baseline_r13 import baseline_policy_hashes\n",
)
replace_once(
    "tests/test_sct_r13_live_wiring.py",
    '''        "profile_builder_sha256": "1" * 64,\n        "retrieval_policy": "Frozen chronological retrieval.",\n        "retrieval_policy_sha256": "2" * 64,\n        "source_cutoff_policy": "Same cutoff as Arm C.",\n        "source_cutoff_sha256": "3" * 64,\n        "admissible_evidence_pool": "Same admitted raw pool as Arm C, without SCT-only claims.",\n        "context_selection_policy": "Deterministic frozen selection.",\n        "context_selection_policy_sha256": "4" * 64,''',
    '''        "retrieval_policy": "Frozen chronological retrieval.",\n        "source_cutoff_policy": "Same cutoff as Arm C.",\n        "admissible_evidence_pool": "Same admitted raw pool as Arm C, without SCT-only claims.",\n        "context_selection_policy": "Deterministic frozen selection.",\n        **baseline_policy_hashes(),''',
)

Path("tests/test_sct_r13_postpass_hardening.py").write_text(r'''import hashlib

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
    from pathlib import Path
    from sct.r13_cli import build_parser
    text = Path("sct/r13_cli.py").read_text(encoding="utf-8")
    block = text[text.index("def _run_component"):text.index("def main")]
    assert 'attempt_lifecycle' not in block
    assert 'finish_r13_component_attempt(store, component=component, receipt=out)' in block
    parser = build_parser()
    open_case = next(a for a in parser._actions if getattr(a, "dest", None) == "cmd").choices["open-case"]
    dests = {a.dest for a in open_case._actions}
    assert "static_profile_file" not in dests
    assert "permitted_history_file" not in dests
    assert {"arm_b_evidence_file", "arm_b_source_cutoff", "arm_b_expected_pool_sha256"} <= dests
''', encoding="utf-8")
