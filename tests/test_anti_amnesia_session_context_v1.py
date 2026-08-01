from __future__ import annotations

import hashlib
import json
from importlib.resources import files as resource_files
from pathlib import Path

import pytest

from continuityos.gate import cli
from continuityos.gate import cold_start
from continuityos.gate import session_context as binding
from continuityos.operational_context import (
    SCHEMA_SPEC as CONTEXT_SPEC_SCHEMA,
    prepare_context_pack,
    validate_context_pack_structure,
)
from continuityos.operational_memory import OperationalMemory

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
            "branch": "gpt/session-context-binding-v1-shadow",
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
    expected_ack = cold_start._expected_ack(cap)
    expected_payload = write_json(
        root / "controller" / "EXPECTED_BOOT_ACK.json", expected_ack
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
    spec_path = tmp_path / "CONTEXT_SPEC.json"
    write_json(spec_path, context_spec())
    context_path = tmp_path / "OPERATIONAL_CONTEXT.json"
    prepare_context_pack(
        db_path=str(db_path),
        capsule_path=capsule_path,
        spec_path=spec_path,
        output_path=context_path,
    )
    return base_root, challenge_path, challenge_sha, capsule_path, context_path


def prepare_binding(tmp_path: Path):
    _root, challenge_path, challenge_sha, capsule_path, context_path = prepare_inputs(
        tmp_path
    )
    out = tmp_path / "bound"
    receipt = binding.prepare_session_context_binding(
        challenge_path,
        context_path,
        out,
        expected_base_challenge_sha256=challenge_sha,
    )
    return out, receipt, challenge_path, capsule_path, context_path


def test_prepare_and_exact_verify_pass(tmp_path):
    out, receipt, *_ = prepare_binding(tmp_path)
    assert receipt["status"] == "SESSION_CONTEXT_CHALLENGE_READY"
    expected = out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json"
    ack = tmp_path / "SESSION_CONTEXT_ACK.json"
    ack.write_bytes(expected.read_bytes())
    verdict = binding.verify_session_context_ack(
        out / "SESSION_CONTEXT_CHALLENGE.json",
        ack,
        expected_challenge_sha256=receipt["challenge_sha256"],
    )
    assert verdict["outcome"] == "PASS"
    assert verdict["status"] == "SESSION_CONTEXT_PASS"
    assert verdict["release_blocked"] is False
    assert verdict["mismatches"] == []


def test_candidate_inventory_has_no_hidden_expected_ack(tmp_path):
    out, _receipt, *_ = prepare_binding(tmp_path)
    candidate = out / "candidate"
    assert {path.name for path in candidate.iterdir()} == {
        "SESSION_CAPSULE.json",
        "OPERATIONAL_CONTEXT.json",
        "SESSION_CONTEXT_BINDING.json",
        "SESSION_CONTEXT_ACK.schema.json",
        "INSTRUCTIONS.md",
    }
    payload = b"\n".join(path.read_bytes() for path in candidate.iterdir())
    assert b"EXPECTED_SESSION_CONTEXT_ACK" not in payload
    assert not (candidate / "EXPECTED_SESSION_CONTEXT_ACK.json").exists()


def test_binding_contains_exact_checkpoint_and_context_hash(tmp_path):
    out, receipt, *_ = prepare_binding(tmp_path)
    manifest = json.loads(
        (out / "candidate" / "SESSION_CONTEXT_BINDING.json").read_text("utf-8")
    )
    context = json.loads(
        (out / "candidate" / "OPERATIONAL_CONTEXT.json").read_text("utf-8")
    )
    assert manifest["binding_id"] == receipt["binding_id"]
    assert manifest["operational_context"]["checkpoint_id"] == "cp-session-context"
    assert manifest["operational_context"]["context_sha256"] == context["context_sha256"]
    assert manifest["operational_context"]["event_cursor"] == context["memory_binding"]["context_event_cursor"]


def test_wrong_base_challenge_hash_fails_closed(tmp_path):
    _root, challenge_path, _challenge_sha, _capsule, context_path = prepare_inputs(tmp_path)
    with pytest.raises(binding.SessionContextError, match="SHA256_MISMATCH"):
        binding.prepare_session_context_binding(
            challenge_path,
            context_path,
            tmp_path / "bound",
            expected_base_challenge_sha256="0" * 64,
        )


def test_context_bound_to_other_capsule_is_rejected(tmp_path):
    _root, challenge_path, challenge_sha, _capsule, context_path = prepare_inputs(tmp_path)
    other_root = tmp_path / "other"
    _r2, _c2, _s2, other_capsule = make_base_challenge(
        other_root, capsule_value=capsule(work_order_id="OTHER-WORK-ORDER")
    )
    db_path = tmp_path / "memory.db"
    other_spec = tmp_path / "OTHER_SPEC.json"
    write_json(other_spec, context_spec())
    other_context = tmp_path / "OTHER_CONTEXT.json"
    prepare_context_pack(
        db_path=str(db_path),
        capsule_path=other_capsule,
        spec_path=other_spec,
        output_path=other_context,
    )
    with pytest.raises(binding.SessionContextError, match="SESSION_BINDING_MISMATCH"):
        binding.prepare_session_context_binding(
            challenge_path,
            other_context,
            tmp_path / "bound",
            expected_base_challenge_sha256=challenge_sha,
        )
    assert context_path.exists()


def test_context_ceiling_escalation_is_rejected(tmp_path):
    _root, challenge_path, challenge_sha, _capsule, context_path = prepare_inputs(tmp_path)
    context = json.loads(context_path.read_text("utf-8"))
    context["ceilings"]["can_trade"] = True
    body = dict(context)
    body.pop("context_sha256")
    context["context_sha256"] = digest(canonical_bytes(body))
    context_path.write_bytes(canonical_bytes(context))
    with pytest.raises(binding.SessionContextError, match="ceilings:VIOLATION"):
        binding.prepare_session_context_binding(
            challenge_path,
            context_path,
            tmp_path / "bound",
            expected_base_challenge_sha256=challenge_sha,
        )


def test_context_pack_structural_hash_tamper_is_rejected(tmp_path):
    _root, challenge_path, challenge_sha, _capsule, context_path = prepare_inputs(tmp_path)
    context = json.loads(context_path.read_text("utf-8"))
    context["work_order_id"] = "TAMPERED"
    context_path.write_bytes(canonical_bytes(context))
    with pytest.raises(binding.SessionContextError, match="context_sha256:MISMATCH"):
        binding.prepare_session_context_binding(
            challenge_path,
            context_path,
            tmp_path / "bound",
            expected_base_challenge_sha256=challenge_sha,
        )


def test_ack_field_mismatch_returns_fail(tmp_path):
    out, receipt, *_ = prepare_binding(tmp_path)
    ack_value = json.loads(
        (out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_text("utf-8")
    )
    ack_value["checkpoint_id"] = "cp-wrong"
    ack = tmp_path / "SESSION_CONTEXT_ACK.json"
    write_json(ack, ack_value)
    verdict = binding.verify_session_context_ack(
        out / "SESSION_CONTEXT_CHALLENGE.json",
        ack,
        expected_challenge_sha256=receipt["challenge_sha256"],
    )
    assert verdict["outcome"] == "FAIL"
    assert verdict["release_blocked"] is True
    assert verdict["mismatches"] == [
        {"path": "/checkpoint_id", "expected": "cp-session-context", "observed": "cp-wrong"}
    ]


def test_ack_extra_key_returns_schema_fail(tmp_path):
    out, receipt, *_ = prepare_binding(tmp_path)
    ack_value = json.loads(
        (out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_text("utf-8")
    )
    ack_value["extra"] = "forbidden"
    ack = tmp_path / "SESSION_CONTEXT_ACK.json"
    write_json(ack, ack_value)
    verdict = binding.verify_session_context_ack(
        out / "SESSION_CONTEXT_CHALLENGE.json",
        ack,
        expected_challenge_sha256=receipt["challenge_sha256"],
    )
    assert verdict["outcome"] == "FAIL"
    assert verdict["checks"][0]["check_id"] == "ack.schema"


def test_bound_challenge_tamper_is_rejected_by_pinned_hash(tmp_path):
    out, receipt, *_ = prepare_binding(tmp_path)
    challenge_path = out / "SESSION_CONTEXT_CHALLENGE.json"
    challenge = json.loads(challenge_path.read_text("utf-8"))
    challenge["binding_id"] = "f" * 64
    challenge_path.write_bytes(canonical_bytes(challenge))
    ack = tmp_path / "ACK.json"
    ack.write_bytes((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_bytes())
    with pytest.raises(binding.SessionContextError, match="SHA256_MISMATCH"):
        binding.verify_session_context_ack(
            challenge_path,
            ack,
            expected_challenge_sha256=receipt["challenge_sha256"],
        )


def test_prepare_refuses_existing_output_and_preserves_inputs(tmp_path):
    _root, challenge_path, challenge_sha, capsule_path, context_path = prepare_inputs(tmp_path)
    before = {
        "challenge": digest(challenge_path.read_bytes()),
        "capsule": digest(capsule_path.read_bytes()),
        "context": digest(context_path.read_bytes()),
    }
    output = tmp_path / "bound"
    output.mkdir()
    with pytest.raises(binding.SessionContextError):
        binding.prepare_session_context_binding(
            challenge_path,
            context_path,
            output,
            expected_base_challenge_sha256=challenge_sha,
        )
    after = {
        "challenge": digest(challenge_path.read_bytes()),
        "capsule": digest(capsule_path.read_bytes()),
        "context": digest(context_path.read_bytes()),
    }
    assert before == after


def test_cli_bind_and_verify_context(tmp_path, capsys):
    _root, challenge_path, challenge_sha, _capsule, context_path = prepare_inputs(tmp_path)
    out = tmp_path / "bound"
    code = cli.main(
        [
            "cold-start",
            "bind-context",
            "--challenge",
            str(challenge_path),
            "--challenge-sha256",
            challenge_sha,
            "--context",
            str(context_path),
            "--output",
            str(out),
        ]
    )
    assert code == 0
    prepare_receipt = json.loads(capsys.readouterr().out)
    ack = tmp_path / "SESSION_CONTEXT_ACK.json"
    ack.write_bytes((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_bytes())
    code = cli.main(
        [
            "cold-start",
            "verify-context",
            "--challenge",
            str(out / "SESSION_CONTEXT_CHALLENGE.json"),
            "--challenge-sha256",
            prepare_receipt["challenge_sha256"],
            "--ack",
            str(ack),
        ]
    )
    assert code == 0
    verdict = json.loads(capsys.readouterr().out)
    assert verdict["status"] == "SESSION_CONTEXT_PASS"


def test_packaged_schemas_are_parseable_and_ack_contract_is_exact(tmp_path):
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
    ack_schema = json.loads(
        resource_files("continuityos.gate.schemas")
        .joinpath("anti_amnesia_session_context_ack_v1.schema.json")
        .read_text("utf-8")
    )
    assert set(ack_schema["required"]) == binding._ACK_KEYS
    out, _receipt, *_ = prepare_binding(tmp_path)
    schema_copy = json.loads(
        (out / "candidate" / "SESSION_CONTEXT_ACK.schema.json").read_text("utf-8")
    )
    assert schema_copy == ack_schema


def test_validate_context_pack_structure_accepts_generated_pack(tmp_path):
    _root, _challenge, _sha, _capsule, context_path = prepare_inputs(tmp_path)
    pack = validate_context_pack_structure(json.loads(context_path.read_text("utf-8")))
    assert pack["schema"] == "CONTINUITYOS_OPERATIONAL_CONTEXT_PACK_V1"
    assert pack["ceilings"]["accepted_truth_owner"] == "CONTROL_CENTER"

@pytest.mark.filterwarnings("ignore:jsonschema.RefResolver is deprecated")
def test_binding_artifacts_match_published_json_schemas(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    out, receipt, *_ = prepare_binding(tmp_path)
    schema_root = Path(binding.__file__).parent / "schemas"
    instances = [
        (
            "anti_amnesia_session_context_binding_v1.schema.json",
            json.loads((out / "candidate" / "SESSION_CONTEXT_BINDING.json").read_text("utf-8")),
        ),
        (
            "anti_amnesia_session_context_ack_v1.schema.json",
            json.loads((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_text("utf-8")),
        ),
        (
            "anti_amnesia_session_context_challenge_v1.schema.json",
            json.loads((out / "SESSION_CONTEXT_CHALLENGE.json").read_text("utf-8")),
        ),
        (
            "anti_amnesia_session_context_prepare_receipt_v1.schema.json",
            receipt,
        ),
    ]
    ack = tmp_path / "SESSION_CONTEXT_ACK.json"
    ack.write_bytes((out / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_bytes())
    verdict = binding.verify_session_context_ack(
        out / "SESSION_CONTEXT_CHALLENGE.json",
        ack,
        expected_challenge_sha256=receipt["challenge_sha256"],
    )
    instances.append(("anti_amnesia_session_context_verdict_v1.schema.json", verdict))
    base_uri = schema_root.as_uri() + "/"
    for name, instance in instances:
        schema = json.loads((schema_root / name).read_text("utf-8"))
        resolver = jsonschema.RefResolver(base_uri=base_uri, referrer=schema)
        jsonschema.Draft7Validator(schema, resolver=resolver).validate(instance)
