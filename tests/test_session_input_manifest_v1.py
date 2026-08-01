from __future__ import annotations

import hashlib
from importlib.resources import files as resource_files
import json
from pathlib import Path

import pytest

from continuityos.operational_context import prepare_context_pack
from continuityos.operational_memory import OperationalMemory
from continuityos.session_input import (
    SCHEMA_MANIFEST,
    SessionInputError,
    prepare_session_input_manifest,
    validate_session_input_manifest,
    verify_session_input_manifest,
)

H1 = "1" * 64
H2 = "2" * 64
T1 = "2026-07-31T20:00:00.000000Z"


def canonical_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def capsule(**overrides):
    value = {
        "schema": "ANTI_AMNESIA_SESSION_CAPSULE_V1",
        "challenge_id": H1,
        "authority_generation": "R63",
        "role": "FABLE-5",
        "active_case": None,
        "case_binding": "NOT_REQUESTED",
        "work_order_id": "FABLE5-COLD-START-COMMON-MEMORY-GATE-V2",
        "role_state": "READY",
        "role_lane": "independent audit",
        "workspace_context_digest": H2,
        "current_pointer_sha256": "3" * 64,
        "latest_checkpoint_id": "cp-session-input",
        "active_open_loop_ids": ["loop-memory"],
        "goal": "Recover bounded operational context from accepted memory.",
        "accepted_decisions": ["R63 remains authority."],
        "rejected_alternatives": ["Do not load the full archive."],
        "allowed_changes": ["Create one BOOT_ACK or bounded output."],
        "forbidden_actions": ["Do not modify repositories.", "Do not apply state."],
        "immutable_decisions": [
            "can_trade=false",
            "capital_permission=DENY",
            "deploy_permission=DENY",
            "self_application=false",
        ],
        "git_baseline": {
            "repository": "bitmaster162/continuityos",
            "branch": "gpt/session-input-manifest-v1-shadow",
            "head": "4" * 40,
            "tree": "5" * 40,
            "porcelain": "",
        },
        "next_action": "Read the bounded context pack.",
        "terminal_condition": "Context pack verified; no state applied.",
        "effect_ceiling": "READ_ONLY",
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "boot_status": "SHADOW_READY_WITH_WARNINGS",
        "boot_outcome": "WOULD_ALLOW_WITH_WARNINGS",
        "boot_warnings": ["R63_RAW_PROVIDER_READBACK_OUTSIDE_SHADOW_PROOF"],
    }
    value.update(overrides)
    return value


def spec(**overrides):
    value = {
        "schema": "CONTINUITYOS_OPERATIONAL_CONTEXT_SPEC_V1",
        "checkpoint_id": "cp-session-input",
        "subjects": ["project:continuityos"],
        "claim_predicates": ["status"],
        "evidence_states": ["VERIFIED"],
        "decision_states": ["HOLD"],
        "include_broker_summary": False,
        "max_claims": 10,
        "max_decisions": 10,
        "max_output_bytes": 131072,
        "valid_at": None,
    }
    value.update(overrides)
    return value


def make_memory(tmp_path: Path) -> Path:
    path = tmp_path / "memory.db"
    evidence = [{"sha256": H1, "locator": "git://continuityos"}]
    with OperationalMemory(str(path)) as db:
        db.record_claim(
            subject_id="project:continuityos",
            predicate="status",
            value="SHADOW_CANDIDATE",
            evidence_state="VERIFIED",
            evidence_refs=evidence,
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="controller",
            valid_from=T1,
            recorded_at=T1,
            claim_id="clm-session-input",
        )
        db.record_decision(
            subject_id="project:continuityos",
            decision_type="live_install",
            state="HOLD",
            value={"install": False},
            rationale="Live install remains gated.",
            authority_class="HUMAN",
            authority_id="Robert",
            authority_ref="decision://hold-live-install",
            evidence_refs=evidence,
            decision_id="dec-session-input",
            recorded_at=T1,
        )
        db.create_checkpoint(
            "session-input-base",
            checkpoint_id="cp-session-input",
            evidence_refs=evidence,
            metadata={"purpose": "session-input"},
        )
    return path


def make_inputs(tmp_path: Path, *, capsule_value=None, spec_value=None):
    db_path = make_memory(tmp_path)
    capsule_path = tmp_path / "SESSION_CAPSULE.json"
    spec_path = tmp_path / "OPERATIONAL_CONTEXT_SPEC.json"
    context_path = tmp_path / "OPERATIONAL_CONTEXT.json"
    capsule_path.write_bytes(canonical_bytes(capsule_value or capsule()))
    spec_path.write_bytes(canonical_bytes(spec_value or spec()))
    prepare_context_pack(
        db_path=str(db_path),
        capsule_path=capsule_path,
        spec_path=spec_path,
        output_path=context_path,
    )
    return db_path, capsule_path, spec_path, context_path


def prepare_manifest(tmp_path: Path):
    _, capsule_path, spec_path, context_path = make_inputs(tmp_path)
    manifest_path = tmp_path / "SESSION_INPUT_MANIFEST.json"
    receipt = prepare_session_input_manifest(
        capsule_path=capsule_path,
        context_path=context_path,
        spec_path=spec_path,
        output_path=manifest_path,
    )
    return receipt, capsule_path, spec_path, context_path, manifest_path


def test_prepare_binds_capsule_context_spec_and_checkpoint(tmp_path):
    receipt, capsule_path, spec_path, context_path, manifest_path = prepare_manifest(tmp_path)
    assert receipt["status"] == "SESSION_INPUT_MANIFEST_READY"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    assert manifest["schema"] == SCHEMA_MANIFEST
    assert manifest["authority_generation"] == "R63"
    assert manifest["session_binding"]["challenge_id"] == H1
    assert manifest["session_binding"]["git_head"] == "4" * 40
    assert manifest["artifact_binding"]["session_capsule"]["sha256"] == sha(capsule_path.read_bytes())
    assert manifest["artifact_binding"]["operational_context"]["file_sha256"] == sha(context_path.read_bytes())
    assert manifest["artifact_binding"]["context_spec"]["sha256"] == sha(spec_path.read_bytes())
    assert manifest["memory_binding"]["checkpoint_id"] == "cp-session-input"
    assert manifest["ceilings"]["accepted_truth_owner"] == "CONTROL_CENTER"
    assert manifest["ceilings"]["can_trade"] is False
    validate_session_input_manifest(manifest)


def test_prepare_is_byte_deterministic(tmp_path):
    _, capsule_path, spec_path, context_path = make_inputs(tmp_path)
    one = tmp_path / "one.json"
    two = tmp_path / "two.json"
    prepare_session_input_manifest(
        capsule_path=capsule_path, context_path=context_path, spec_path=spec_path, output_path=one
    )
    prepare_session_input_manifest(
        capsule_path=capsule_path, context_path=context_path, spec_path=spec_path, output_path=two
    )
    assert one.read_bytes() == two.read_bytes()


def test_verify_requires_controller_pinned_file_sha(tmp_path):
    receipt, capsule_path, spec_path, context_path, manifest_path = prepare_manifest(tmp_path)
    verdict = verify_session_input_manifest(
        capsule_path=capsule_path,
        context_path=context_path,
        spec_path=spec_path,
        manifest_path=manifest_path,
        expected_manifest_file_sha256=receipt["output_sha256"],
    )
    assert verdict["status"] == "SESSION_INPUT_VERIFY_PASS"
    assert verdict["ok"] is True
    with pytest.raises(SessionInputError, match="PINNED_SHA256_MISMATCH"):
        verify_session_input_manifest(
            capsule_path=capsule_path,
            context_path=context_path,
            spec_path=spec_path,
            manifest_path=manifest_path,
            expected_manifest_file_sha256="0" * 64,
        )


def test_tampered_manifest_returns_exact_verify_fail(tmp_path):
    receipt, capsule_path, spec_path, context_path, manifest_path = prepare_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["memory_binding"]["checkpoint_id"] = "cp-other"
    body = {key: manifest[key] for key in manifest if key != "manifest_sha256"}
    manifest["manifest_sha256"] = sha(canonical_bytes(body))
    manifest_path.write_bytes(canonical_bytes(manifest))
    pinned = sha(manifest_path.read_bytes())
    verdict = verify_session_input_manifest(
        capsule_path=capsule_path,
        context_path=context_path,
        spec_path=spec_path,
        manifest_path=manifest_path,
        expected_manifest_file_sha256=pinned,
    )
    assert verdict["status"] == "SESSION_INPUT_VERIFY_FAIL"
    assert verdict["ok"] is False


def test_tampered_context_self_hash_is_rejected(tmp_path):
    _, capsule_path, spec_path, context_path = make_inputs(tmp_path)
    context = json.loads(context_path.read_text("utf-8"))
    context["claims"][0]["value"] = "TAMPERED"
    context_path.write_bytes(canonical_bytes(context))
    with pytest.raises(SessionInputError, match="SELF_HASH_MISMATCH"):
        prepare_session_input_manifest(
            capsule_path=capsule_path,
            context_path=context_path,
            spec_path=spec_path,
            output_path=tmp_path / "manifest.json",
        )


def test_context_bound_to_different_capsule_is_rejected(tmp_path):
    _, capsule_path, spec_path, context_path = make_inputs(tmp_path)
    changed = capsule(challenge_id="9" * 64)
    capsule_path.write_bytes(canonical_bytes(changed))
    with pytest.raises(SessionInputError, match="session_binding:MISMATCH"):
        prepare_session_input_manifest(
            capsule_path=capsule_path,
            context_path=context_path,
            spec_path=spec_path,
            output_path=tmp_path / "manifest.json",
        )


def test_context_bound_to_different_spec_is_rejected(tmp_path):
    _, capsule_path, spec_path, context_path = make_inputs(tmp_path)
    spec_path.write_bytes(canonical_bytes(spec(max_claims=9)))
    with pytest.raises(SessionInputError, match="SPEC_SHA256_MISMATCH"):
        prepare_session_input_manifest(
            capsule_path=capsule_path,
            context_path=context_path,
            spec_path=spec_path,
            output_path=tmp_path / "manifest.json",
        )


def test_noncanonical_json_is_rejected(tmp_path):
    _, capsule_path, spec_path, context_path = make_inputs(tmp_path)
    capsule_path.write_text(json.dumps(capsule(), indent=2), encoding="utf-8")
    with pytest.raises(SessionInputError, match="NON_CANONICAL_JSON"):
        prepare_session_input_manifest(
            capsule_path=capsule_path,
            context_path=context_path,
            spec_path=spec_path,
            output_path=tmp_path / "manifest.json",
        )


def test_existing_output_is_never_overwritten(tmp_path):
    _, capsule_path, spec_path, context_path = make_inputs(tmp_path)
    output = tmp_path / "manifest.json"
    output.write_text("keep", encoding="utf-8")
    with pytest.raises(SessionInputError, match="TARGET_ALREADY_EXISTS"):
        prepare_session_input_manifest(
            capsule_path=capsule_path,
            context_path=context_path,
            spec_path=spec_path,
            output_path=output,
        )
    assert output.read_text("utf-8") == "keep"


def test_symlink_input_is_refused(tmp_path):
    _, capsule_path, spec_path, context_path = make_inputs(tmp_path)
    link = tmp_path / "capsule-link.json"
    try:
        link.symlink_to(capsule_path)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(SessionInputError, match="SYMLINK_REFUSED"):
        prepare_session_input_manifest(
            capsule_path=link,
            context_path=context_path,
            spec_path=spec_path,
            output_path=tmp_path / "manifest.json",
        )


def test_manifest_extra_key_and_ceiling_escalation_rejected(tmp_path):
    _, _, _, _, manifest_path = prepare_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["extra"] = True
    with pytest.raises(SessionInputError, match="KEYS"):
        validate_session_input_manifest(manifest)
    manifest.pop("extra")
    manifest["ceilings"]["can_trade"] = True
    body = {key: manifest[key] for key in manifest if key != "manifest_sha256"}
    manifest["manifest_sha256"] = sha(canonical_bytes(body))
    with pytest.raises(SessionInputError, match="ceilings:VIOLATION"):
        validate_session_input_manifest(manifest)


def test_packaged_schema_is_strict_and_validates_manifest(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    _, _, _, _, manifest_path = prepare_manifest(tmp_path)
    schema_path = resource_files("continuityos.session_input_schemas").joinpath(
        "session_input_manifest_v1.schema.json"
    )
    schema = json.loads(schema_path.read_text("utf-8"))
    manifest = json.loads(manifest_path.read_text("utf-8"))
    jsonschema.Draft7Validator(schema).validate(manifest)
    broken = dict(manifest)
    broken["extra"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft7Validator(schema).validate(broken)


def test_cli_prepare_and_verify(tmp_path, capsys):
    from continuityos.session_input import main

    _, capsule_path, spec_path, context_path = make_inputs(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    assert main([
        "prepare",
        "--capsule", str(capsule_path),
        "--context", str(context_path),
        "--spec", str(spec_path),
        "--out", str(manifest_path),
    ]) == 0
    prepare_receipt = json.loads(capsys.readouterr().out)
    assert main([
        "verify",
        "--capsule", str(capsule_path),
        "--context", str(context_path),
        "--spec", str(spec_path),
        "--manifest", str(manifest_path),
        "--manifest-sha256", prepare_receipt["output_sha256"],
    ]) == 0
    verify_receipt = json.loads(capsys.readouterr().out)
    assert verify_receipt["status"] == "SESSION_INPUT_VERIFY_PASS"
