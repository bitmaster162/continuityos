from __future__ import annotations

import hashlib
import json
from importlib.resources import files as resource_files
from pathlib import Path

import pytest

from continuityos.gate import cli, cold_start
from continuityos.gate import session_context as binding
from continuityos.operational_context import (
    SCHEMA_SPEC as CONTEXT_SPEC_SCHEMA,
    prepare_context_pack,
    verify_context_pack,
)
from continuityos.operational_memory import OperationalMemory
from continuityos.session_input import prepare_session_input_manifest

H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
T1 = "2026-08-01T00:00:00.000000Z"


def canonical_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_json(path: Path, value) -> bytes:
    payload = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return payload


def capsule(**overrides):
    value = {
        "schema": "ANTI_AMNESIA_SESSION_CAPSULE_V1",
        "challenge_id": H1,
        "authority_generation": "R63",
        "role": "FABLE-5",
        "active_case": None,
        "case_binding": "NOT_REQUESTED",
        "work_order_id": "FABLE5-CONTEXT-BINDING-V1",
        "role_state": "READY",
        "role_lane": "independent memory audit",
        "workspace_context_digest": H2,
        "current_pointer_sha256": H3,
        "latest_checkpoint_id": "cp-session-context",
        "active_open_loop_ids": ["loop-memory"],
        "goal": "Recover one bounded memory context before work.",
        "accepted_decisions": ["R63 remains authority."],
        "rejected_alternatives": ["Do not load the full archive."],
        "allowed_changes": ["Create SESSION_CONTEXT_ACK.json only."],
        "forbidden_actions": ["Do not modify repositories.", "Do not apply state."],
        "immutable_decisions": [
            "can_trade=false",
            "capital_permission=DENY",
            "deploy_permission=DENY",
            "self_application=false",
        ],
        "git_baseline": {
            "repository": "bitmaster162/continuityos",
            "branch": "gpt/session-context-ack-v1-shadow",
            "head": "4" * 40,
            "tree": "5" * 40,
            "porcelain": "",
        },
        "next_action": "Read the context pack and acknowledge its exact binding.",
        "terminal_condition": "SESSION_CONTEXT_ACK.json emitted; stop.",
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


def make_base_challenge(tmp_path: Path, capsule_value=None):
    root = tmp_path / "base-challenge"
    cap = capsule_value or capsule()
    cap_payload = write_json(root / "candidate" / "SESSION_CAPSULE.json", cap)
    expected_payload = write_json(
        root / "controller" / "EXPECTED_BOOT_ACK.json", cold_start._expected_ack(cap)
    )
    challenge = {
        "schema": cold_start.SCHEMA_CHALLENGE,
        "challenge_id": cap["challenge_id"],
        "gate": "ANTI_AMNESIA_GATE_V1",
        "mode": "SHADOW",
        "authority_generation": "R63",
        "boot_receipt": {"source_name": "BOOT_RECEIPT.json", "sha256": "6" * 64},
        "session_spec": {"source_name": "SPEC.json", "sha256": "7" * 64},
        "candidate_capsule": {
            "path": "candidate/SESSION_CAPSULE.json",
            "sha256": digest(cap_payload),
        },
        "controller_expected_ack": {
            "path": "controller/EXPECTED_BOOT_ACK.json",
            "sha256": digest(expected_payload),
        },
        "candidate_instructions": {
            "output_schema": cold_start.SCHEMA_ACK,
            "output_filename": "BOOT_ACK.json",
            "no_external_context": True,
            "no_archive_access": True,
            "no_repo_writes": True,
        },
        "live_state_modified": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }
    challenge_path = root / "COLD_START_CHALLENGE.json"
    challenge_payload = write_json(challenge_path, challenge)
    return root, challenge_path, digest(challenge_payload), root / "candidate" / "SESSION_CAPSULE.json"


def ref():
    return [{"sha256": "8" * 64, "locator": "evidence://session-context"}]


def make_memory(tmp_path: Path) -> Path:
    db_path = tmp_path / "memory.db"
    with OperationalMemory(str(db_path)) as memory:
        memory.record_claim(
            subject_id="role:FABLE-5",
            predicate="memory_gate",
            value="READY_FOR_CONTEXT_BINDING",
            scope="cold-start",
            evidence_state="VERIFIED",
            evidence_refs=ref(),
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="controller",
            valid_from=T1,
            recorded_at=T1,
            claim_id="clm-session-context",
        )
        memory.record_decision(
            subject_id="role:FABLE-5",
            decision_type="live_install",
            state="HOLD",
            value={"install": False},
            rationale="Shadow only.",
            authority_class="HUMAN",
            authority_id="Robert",
            authority_ref="decision://session-context-hold",
            evidence_refs=ref(),
            decision_id="dec-session-context",
            recorded_at=T1,
        )
        memory.create_checkpoint(
            "session-context-binding",
            checkpoint_id="cp-session-context",
            evidence_refs=ref(),
            metadata={"purpose": "session-context"},
        )
    return db_path


def context_spec():
    return {
        "schema": CONTEXT_SPEC_SCHEMA,
        "checkpoint_id": "cp-session-context",
        "subjects": ["role:FABLE-5"],
        "claim_predicates": ["memory_gate"],
        "evidence_states": ["VERIFIED"],
        "decision_states": ["HOLD"],
        "include_broker_summary": False,
        "max_claims": 4,
        "max_decisions": 4,
        "max_output_bytes": 65536,
        "valid_at": None,
    }


def prepare_inputs(tmp_path: Path, *, capsule_value=None):
    base_root, challenge_path, challenge_sha, capsule_path = make_base_challenge(
        tmp_path, capsule_value=capsule_value
    )
    db_path = make_memory(tmp_path)
    spec_path = tmp_path / "OPERATIONAL_CONTEXT_SPEC.json"
    write_json(spec_path, context_spec())
    context_path = tmp_path / "OPERATIONAL_CONTEXT.json"
    prepare_context_pack(
        db_path=str(db_path),
        capsule_path=capsule_path,
        spec_path=spec_path,
        output_path=context_path,
    )
    context_verify_path = tmp_path / "OPERATIONAL_CONTEXT_VERIFY_RECEIPT.json"
    write_json(
        context_verify_path,
        verify_context_pack(
            db_path=str(db_path),
            capsule_path=capsule_path,
            spec_path=spec_path,
            context_path=context_path,
        ),
    )
    manifest_path = tmp_path / "SESSION_INPUT_MANIFEST.json"
    manifest_receipt = prepare_session_input_manifest(
        capsule_path=capsule_path,
        context_path=context_path,
        spec_path=spec_path,
        context_verification_path=context_verify_path,
        output_path=manifest_path,
    )
    return {
        "base_root": base_root,
        "challenge_path": challenge_path,
        "challenge_sha": challenge_sha,
        "capsule_path": capsule_path,
        "db_path": db_path,
        "spec_path": spec_path,
        "context_path": context_path,
        "context_verify_path": context_verify_path,
        "manifest_path": manifest_path,
        "manifest_sha": manifest_receipt["output_sha256"],
    }


def bind(tmp_path: Path, inputs=None):
    inputs = inputs or prepare_inputs(tmp_path)
    out = tmp_path / "bound"
    receipt = binding.prepare_session_context_binding(
        inputs["challenge_path"],
        inputs["context_path"],
        inputs["manifest_path"],
        inputs["spec_path"],
        inputs["context_verify_path"],
        out,
        expected_base_challenge_sha256=inputs["challenge_sha"],
        expected_session_input_manifest_sha256=inputs["manifest_sha"],
    )
    return out, receipt, inputs


def test_prepare_and_exact_verify_pass(tmp_path):
    out, receipt, _ = bind(tmp_path)
    assert receipt["status"] == "SESSION_CONTEXT_CHALLENGE_READY"
    ack = tmp_path / "SESSION_CONTEXT_ACK.json"
    ack.write_bytes((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_bytes())
    verdict = binding.verify_session_context_ack(
        out / "SESSION_CONTEXT_CHALLENGE.json",
        ack,
        expected_challenge_sha256=receipt["challenge_sha256"],
    )
    assert verdict["outcome"] == "PASS"
    assert verdict["status"] == "SESSION_CONTEXT_PASS"
    assert verdict["release_blocked"] is False
    assert verdict["mismatches"] == []


def test_candidate_inventory_has_no_hidden_controller_artifacts(tmp_path):
    out, _, _ = bind(tmp_path)
    candidate = out / "candidate"
    assert {path.name for path in candidate.iterdir()} == {
        "SESSION_CAPSULE.json",
        "OPERATIONAL_CONTEXT.json",
        "SESSION_INPUT_MANIFEST.json",
        "SESSION_CONTEXT_BINDING.json",
        "SESSION_CONTEXT_ACK.schema.json",
        "INSTRUCTIONS.md",
    }
    payload = b"\n".join(path.read_bytes() for path in candidate.iterdir())
    assert b"EXPECTED_SESSION_CONTEXT_ACK" not in payload
    assert b"OPERATIONAL_CONTEXT_VERIFY_RECEIPT" in payload  # logical name/hash only
    assert not (candidate / "OPERATIONAL_CONTEXT_VERIFY_RECEIPT.json").exists()
    assert not (candidate / "OPERATIONAL_CONTEXT_SPEC.json").exists()


def test_binding_uses_canonical_session_input_manifest(tmp_path):
    out, receipt, inputs = bind(tmp_path)
    manifest = json.loads((out / "candidate" / "SESSION_INPUT_MANIFEST.json").read_text("utf-8"))
    envelope = json.loads((out / "candidate" / "SESSION_CONTEXT_BINDING.json").read_text("utf-8"))
    assert envelope["session_input_manifest"]["file_sha256"] == inputs["manifest_sha"]
    assert envelope["session_input_manifest"]["manifest_sha256"] == manifest["manifest_sha256"]
    assert receipt["context_verification_receipt_sha256"] == manifest["artifact_binding"]["context_verification"]["sha256"]
    expected = json.loads((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_text("utf-8"))
    assert expected["session_input_manifest_file_sha256"] == inputs["manifest_sha"]
    assert expected["checkpoint_id"] == "cp-session-context"
    assert expected["effect_ceiling"] == "READ_ONLY"


def test_wrong_base_or_manifest_pin_fails_closed(tmp_path):
    inputs = prepare_inputs(tmp_path)
    with pytest.raises(binding.SessionContextError, match="base_challenge:SHA256_MISMATCH"):
        binding.prepare_session_context_binding(
            inputs["challenge_path"], inputs["context_path"], inputs["manifest_path"],
            inputs["spec_path"], inputs["context_verify_path"], tmp_path / "one",
            expected_base_challenge_sha256="0" * 64,
            expected_session_input_manifest_sha256=inputs["manifest_sha"],
        )
    with pytest.raises(binding.SessionContextError, match="PINNED_SHA256_MISMATCH"):
        binding.prepare_session_context_binding(
            inputs["challenge_path"], inputs["context_path"], inputs["manifest_path"],
            inputs["spec_path"], inputs["context_verify_path"], tmp_path / "two",
            expected_base_challenge_sha256=inputs["challenge_sha"],
            expected_session_input_manifest_sha256="0" * 64,
        )


def test_forged_context_verify_receipt_is_rejected(tmp_path):
    inputs = prepare_inputs(tmp_path)
    receipt = json.loads(inputs["context_verify_path"].read_text("utf-8"))
    receipt["ok"] = False
    receipt["status"] = "OPERATIONAL_CONTEXT_VERIFY_FAIL"
    write_json(inputs["context_verify_path"], receipt)
    with pytest.raises(binding.SessionContextError, match="context_verification:NOT_EXACT_PASS"):
        binding.prepare_session_context_binding(
            inputs["challenge_path"], inputs["context_path"], inputs["manifest_path"],
            inputs["spec_path"], inputs["context_verify_path"], tmp_path / "bound",
            expected_base_challenge_sha256=inputs["challenge_sha"],
            expected_session_input_manifest_sha256=inputs["manifest_sha"],
        )


def test_manifest_from_other_capsule_is_rejected(tmp_path):
    inputs = prepare_inputs(tmp_path)
    other = tmp_path / "other"
    other_inputs = prepare_inputs(other, capsule_value=capsule(work_order_id="OTHER"))
    with pytest.raises(binding.SessionContextError):
        binding.prepare_session_context_binding(
            inputs["challenge_path"], other_inputs["context_path"], other_inputs["manifest_path"],
            other_inputs["spec_path"], other_inputs["context_verify_path"], tmp_path / "bound",
            expected_base_challenge_sha256=inputs["challenge_sha"],
            expected_session_input_manifest_sha256=other_inputs["manifest_sha"],
        )


def test_ack_mismatch_and_extra_key_fail(tmp_path):
    out, receipt, _ = bind(tmp_path)
    expected = json.loads((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_text("utf-8"))
    wrong = dict(expected)
    wrong["checkpoint_id"] = "cp-wrong"
    ack = tmp_path / "ACK.json"
    write_json(ack, wrong)
    verdict = binding.verify_session_context_ack(
        out / "SESSION_CONTEXT_CHALLENGE.json", ack,
        expected_challenge_sha256=receipt["challenge_sha256"],
    )
    assert verdict["status"] == "SESSION_CONTEXT_FAIL"
    assert verdict["mismatches"] == [{"path": "/checkpoint_id", "expected": "cp-session-context", "observed": "cp-wrong"}]
    extra = dict(expected)
    extra["extra"] = True
    write_json(tmp_path / "EXTRA.json", extra)
    verdict = binding.verify_session_context_ack(
        out / "SESSION_CONTEXT_CHALLENGE.json", tmp_path / "EXTRA.json",
        expected_challenge_sha256=receipt["challenge_sha256"],
    )
    assert verdict["status"] == "SESSION_CONTEXT_FAIL"
    assert verdict["checks"][0]["check_id"] == "ack.schema"


def test_challenge_or_candidate_tamper_fails_closed(tmp_path):
    out, receipt, _ = bind(tmp_path)
    challenge_path = out / "SESSION_CONTEXT_CHALLENGE.json"
    challenge = json.loads(challenge_path.read_text("utf-8"))
    challenge["binding_id"] = "f" * 64
    write_json(challenge_path, challenge)
    ack = tmp_path / "ACK.json"
    ack.write_bytes((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_bytes())
    with pytest.raises(binding.SessionContextError, match="SHA256_MISMATCH"):
        binding.verify_session_context_ack(
            challenge_path, ack, expected_challenge_sha256=receipt["challenge_sha256"]
        )


def test_prepare_refuses_existing_output_and_preserves_inputs(tmp_path):
    inputs = prepare_inputs(tmp_path)
    protected = [inputs[key] for key in ("challenge_path", "capsule_path", "context_path", "manifest_path", "spec_path", "context_verify_path")]
    before = {str(path): digest(path.read_bytes()) for path in protected}
    out = tmp_path / "bound"
    out.mkdir()
    with pytest.raises(binding.SessionContextError, match="TARGET_ALREADY_EXISTS"):
        binding.prepare_session_context_binding(
            inputs["challenge_path"], inputs["context_path"], inputs["manifest_path"],
            inputs["spec_path"], inputs["context_verify_path"], out,
            expected_base_challenge_sha256=inputs["challenge_sha"],
            expected_session_input_manifest_sha256=inputs["manifest_sha"],
        )
    assert before == {str(path): digest(path.read_bytes()) for path in protected}


def test_cli_bind_and_verify_context(tmp_path, capsys):
    inputs = prepare_inputs(tmp_path)
    out = tmp_path / "bound"
    assert cli.main([
        "cold-start", "bind-context",
        "--challenge", str(inputs["challenge_path"]),
        "--challenge-sha256", inputs["challenge_sha"],
        "--context", str(inputs["context_path"]),
        "--manifest", str(inputs["manifest_path"]),
        "--manifest-sha256", inputs["manifest_sha"],
        "--context-spec", str(inputs["spec_path"]),
        "--context-verification", str(inputs["context_verify_path"]),
        "--output", str(out),
    ]) == 0
    prepare_receipt = json.loads(capsys.readouterr().out)
    ack = tmp_path / "ACK.json"
    ack.write_bytes((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_bytes())
    assert cli.main([
        "cold-start", "verify-context",
        "--challenge", str(out / "SESSION_CONTEXT_CHALLENGE.json"),
        "--challenge-sha256", prepare_receipt["challenge_sha256"],
        "--ack", str(ack),
    ]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "SESSION_CONTEXT_PASS"


def test_packaged_schemas_are_strict_and_ack_contract_is_exact(tmp_path):
    names = [
        "anti_amnesia_session_context_ack_v1.schema.json",
        "anti_amnesia_session_context_binding_v1.schema.json",
        "anti_amnesia_session_context_challenge_v1.schema.json",
        "anti_amnesia_session_context_prepare_receipt_v1.schema.json",
        "anti_amnesia_session_context_verdict_v1.schema.json",
    ]
    for name in names:
        parsed = json.loads(resource_files("continuityos.gate.schemas").joinpath(name).read_text("utf-8"))
        assert parsed["additionalProperties"] is False
    ack_schema = json.loads(resource_files("continuityos.gate.schemas").joinpath(names[0]).read_text("utf-8"))
    assert set(ack_schema["required"]) == binding._ACK_KEYS
    out, _, _ = bind(tmp_path)
    assert json.loads((out / "candidate" / "SESSION_CONTEXT_ACK.schema.json").read_text("utf-8")) == ack_schema


@pytest.mark.filterwarnings("ignore:jsonschema.RefResolver is deprecated")
def test_artifacts_match_published_json_schemas(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    out, receipt, _ = bind(tmp_path)
    schema_root = Path(binding.__file__).parent / "schemas"
    instances = [
        ("anti_amnesia_session_context_binding_v1.schema.json", json.loads((out / "candidate" / "SESSION_CONTEXT_BINDING.json").read_text("utf-8"))),
        ("anti_amnesia_session_context_ack_v1.schema.json", json.loads((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_text("utf-8"))),
        ("anti_amnesia_session_context_challenge_v1.schema.json", json.loads((out / "SESSION_CONTEXT_CHALLENGE.json").read_text("utf-8"))),
        ("anti_amnesia_session_context_prepare_receipt_v1.schema.json", receipt),
    ]
    ack = tmp_path / "ACK.json"
    ack.write_bytes((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_bytes())
    verdict = binding.verify_session_context_ack(
        out / "SESSION_CONTEXT_CHALLENGE.json", ack,
        expected_challenge_sha256=receipt["challenge_sha256"],
    )
    instances.append(("anti_amnesia_session_context_verdict_v1.schema.json", verdict))
    for name, instance in instances:
        jsonschema.Draft7Validator(json.loads((schema_root / name).read_text("utf-8"))).validate(instance)
