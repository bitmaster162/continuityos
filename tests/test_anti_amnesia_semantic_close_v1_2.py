from __future__ import annotations

import hashlib
import json
from importlib.resources import files as resource_files
from pathlib import Path

import pytest

from continuityos.gate import anti_amnesia as gate
from continuityos.gate import cli, cold_start
from continuityos.gate import semantic_close as v11
from continuityos.gate import semantic_close_v12 as v12
from continuityos.gate import session_context
from continuityos.operational_context import (
    SCHEMA_SPEC as CONTEXT_SPEC_SCHEMA,
    prepare_context_pack,
    verify_context_pack,
)
from continuityos.operational_memory import OperationalMemory
from continuityos.session_input import prepare_session_input_manifest

ROLE = "CODEX-01"
CASE_ID = "WO-READ-ONLY-001"
H1 = "1" * 64
T1 = "2026-08-01T00:00:00.000000Z"

POINTER_EFFECT = {
    "auto_dispatch": False,
    "auto_accept": False,
    "push": "DENY",
    "deploy": "DENY",
    "can_trade": False,
    "capital_permission": "DENY",
}
GLOBAL_EFFECT = {**POINTER_EFFECT, "self_application": False}


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


def descriptor(path: str, payload: bytes):
    return {"path": path, "size_bytes": len(payload), "sha256": digest(payload)}


def make_control_root(tmp_path: Path) -> Path:
    root = tmp_path / "control"
    root.mkdir()
    role_record = {"state": "READY", "lane": "ContinuityOS", "case_id": CASE_ID}
    documents = {
        "manifest": ("MANIFEST.json", {"schema": "CONTROL_ROOT_MANIFEST_R63"}),
        "current_state": (
            "CURRENT_STATE.json",
            {
                "schema": "CONTROL_CURRENT_STATE_R63",
                "generation": "R63",
                "global_effect_ceiling": GLOBAL_EFFECT,
            },
        ),
        "role_index": (
            "ROLE_INDEX.json",
            {
                "schema": "CONTROL_ROLE_INDEX_R63",
                "generation": "R63",
                "role_views": {
                    ROLE: {"path": "ROLE_VIEWS.json", "json_pointer": f"/roles/{ROLE}"}
                },
            },
        ),
        "role_views": (
            "ROLE_VIEWS.json",
            {
                "schema": "CONTROL_ROLE_VIEWS_R63",
                "generation": "R63",
                "global_effect_ceiling": GLOBAL_EFFECT,
                "roles": {ROLE: role_record},
            },
        ),
        "generation_ledger": (
            "R63/R63_GENERATION_LEDGER.json",
            {
                "schema": "control_canter.generation_ledger.v1",
                "generation": "R63",
                "generations": [
                    {
                        "generation": "R63",
                        "plane": "AUTHORITY",
                        "status": "CURRENT_AUTHORITY_PLANE",
                    }
                ],
            },
        ),
        "packet_manifest": ("R63/MANIFEST.json", {"schema": "CONTROL_PACKET_MANIFEST_R63"}),
    }
    descriptors = {}
    for name, (logical, document) in documents.items():
        descriptors[name] = descriptor(logical, write_json(root / logical, document))
    pointer = {
        "schema": "CONTROL_CURRENT_POINTER_R63",
        "generation": "R63",
        **descriptors,
        "ready_protocol": {"marker": "R63/READY.json"},
        "effect_ceiling": POINTER_EFFECT,
    }
    pointer_payload = write_json(root / "CURRENT_POINTER.json", pointer)
    write_json(
        root / "R63" / "READY.json",
        {
            "schema": "CONTROL_CANTER_R63_READY",
            "generation": "R63",
            "created_last": True,
            "pointer_sha256": digest(pointer_payload),
            "pointer_size_bytes": len(pointer_payload),
            "status": "R63_PROVIDER_READBACK_VERIFIED",
            "can_trade": False,
            "capital_permission": "DENY",
        },
    )
    return root


def make_workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    (root / "00_CANON").mkdir(parents=True)
    (root / "01_RUNTIME").mkdir()
    (root / "00_CANON" / "HUMAN_CANON.md").write_text("# Human\n", encoding="utf-8")
    (root / "00_CANON" / "INVARIANTS.md").write_text("# Invariants\n", encoding="utf-8")
    (root / "00_CANON" / "INTERNAL_AGENTS.md").write_text("# Agents\n", encoding="utf-8")
    write_json(root / "01_RUNTIME" / "state.json", {"last_checkpoint_id": "cp-1"})
    write_json(root / "01_RUNTIME" / "projects.json", {"continuity": {"status": "active"}})
    write_json(
        root / "01_RUNTIME" / "open_loops.json",
        [{"id": "loop-1", "title": "Review", "status": "open", "next_action": "Review"}],
    )
    (root / "01_RUNTIME" / "checkpoints.jsonl").write_bytes(
        canonical_bytes({"checkpoint_id": "cp-1"}) + b"\n"
    )
    return root


def make_policy(path: Path):
    policy = {
        "schema": v11.SCHEMA_POLICY,
        "authority_generation": "R63",
        "policy_id": "read-only-policy",
        "roles": {
            ROLE: {
                "allow_no_case": False,
                "allowed_delta_prefixes": ["/projects/continuityos"],
                "allowed_git_paths": ["continuityos/"],
                "allowed_effect_classes": ["REVERSIBLE"],
            }
        },
    }
    write_json(path, policy)
    return policy


def make_memory(tmp_path: Path) -> Path:
    db = tmp_path / "memory.db"
    refs = [{"sha256": "8" * 64, "locator": "evidence://semantic-v12"}]
    with OperationalMemory(str(db)) as memory:
        memory.record_claim(
            subject_id=f"role:{ROLE}",
            predicate="task_gate",
            value="READ_ONLY",
            scope="semantic-close-v12",
            evidence_state="VERIFIED",
            evidence_refs=refs,
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="controller",
            valid_from=T1,
            recorded_at=T1,
            claim_id="clm-v12",
        )
        memory.record_decision(
            subject_id=f"role:{ROLE}",
            decision_type="write_permission",
            state="HOLD",
            value={"write": False},
            rationale="Read-only session.",
            authority_class="HUMAN",
            authority_id="Robert",
            authority_ref="decision://read-only",
            evidence_refs=refs,
            decision_id="dec-v12",
            recorded_at=T1,
        )
        memory.create_checkpoint(
            "semantic-close-v12",
            checkpoint_id="cp-v12",
            evidence_refs=refs,
            metadata={"purpose": "read-only-return"},
        )
    return db


def make_session_chain(tmp_path: Path, boot):
    capsule = {
        "schema": "ANTI_AMNESIA_SESSION_CAPSULE_V1",
        "challenge_id": H1,
        "authority_generation": "R63",
        "role": ROLE,
        "active_case": CASE_ID,
        "case_binding": "EXACT_STRUCTURED_MATCH",
        "work_order_id": CASE_ID,
        "role_state": "READY",
        "role_lane": "read-only audit",
        "workspace_context_digest": boot["workspace"]["context_digest"],
        "current_pointer_sha256": boot["authority"]["pointer"]["sha256"],
        "latest_checkpoint_id": "cp-v12",
        "active_open_loop_ids": ["loop-1"],
        "goal": "Perform one bounded read-only audit.",
        "accepted_decisions": ["R63 remains authority."],
        "rejected_alternatives": ["Do not mutate source or state."],
        "allowed_changes": ["Create the return evidence package only."],
        "forbidden_actions": ["Do not modify repositories.", "Do not apply state."],
        "immutable_decisions": [
            "can_trade=false",
            "capital_permission=DENY",
            "deploy_permission=DENY",
            "self_application=false",
        ],
        "git_baseline": {
            "repository": "bitmaster162/continuityos",
            "branch": "gpt/semantic-close-v1.2-shadow",
            "head": "4" * 40,
            "tree": "5" * 40,
            "porcelain": "",
        },
        "next_action": "Execute read-only work and return evidence.",
        "terminal_condition": "Return package emitted; stop.",
        "effect_ceiling": "READ_ONLY",
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "boot_status": boot["status"],
        "boot_outcome": boot["outcome"],
        "boot_warnings": boot["warnings"],
    }
    base = tmp_path / "base-challenge"
    capsule_payload = write_json(base / "candidate" / "SESSION_CAPSULE.json", capsule)
    expected_payload = write_json(
        base / "controller" / "EXPECTED_BOOT_ACK.json", cold_start._expected_ack(capsule)
    )
    challenge = {
        "schema": cold_start.SCHEMA_CHALLENGE,
        "challenge_id": H1,
        "gate": gate.GATE,
        "mode": gate.MODE,
        "authority_generation": "R63",
        "boot_receipt": {"source_name": "BOOT_RECEIPT.json", "sha256": "6" * 64},
        "session_spec": {"source_name": "SPEC.json", "sha256": "7" * 64},
        "candidate_capsule": {
            "path": "candidate/SESSION_CAPSULE.json",
            "sha256": digest(capsule_payload),
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
    base_challenge_path = base / "COLD_START_CHALLENGE.json"
    base_challenge_sha = digest(write_json(base_challenge_path, challenge))

    db = make_memory(tmp_path)
    spec = {
        "schema": CONTEXT_SPEC_SCHEMA,
        "checkpoint_id": "cp-v12",
        "subjects": [f"role:{ROLE}"],
        "claim_predicates": ["task_gate"],
        "evidence_states": ["VERIFIED"],
        "decision_states": ["HOLD"],
        "include_broker_summary": False,
        "max_claims": 4,
        "max_decisions": 4,
        "max_output_bytes": 65536,
        "valid_at": None,
    }
    spec_path = tmp_path / "OPERATIONAL_CONTEXT_SPEC.json"
    write_json(spec_path, spec)
    context_path = tmp_path / "OPERATIONAL_CONTEXT.json"
    prepare_context_pack(
        db_path=str(db),
        capsule_path=base / "candidate" / "SESSION_CAPSULE.json",
        spec_path=spec_path,
        output_path=context_path,
    )
    context_verify_path = tmp_path / "OPERATIONAL_CONTEXT_VERIFY_RECEIPT.json"
    write_json(
        context_verify_path,
        verify_context_pack(
            db_path=str(db),
            capsule_path=base / "candidate" / "SESSION_CAPSULE.json",
            spec_path=spec_path,
            context_path=context_path,
        ),
    )
    manifest_path = tmp_path / "SESSION_INPUT_MANIFEST.json"
    manifest_receipt = prepare_session_input_manifest(
        capsule_path=base / "candidate" / "SESSION_CAPSULE.json",
        context_path=context_path,
        spec_path=spec_path,
        context_verification_path=context_verify_path,
        output_path=manifest_path,
    )
    bound = tmp_path / "bound-context"
    prepare_receipt = session_context.prepare_session_context_binding(
        base_challenge_path,
        context_path,
        manifest_path,
        spec_path,
        context_verify_path,
        bound,
        expected_base_challenge_sha256=base_challenge_sha,
        expected_session_input_manifest_sha256=manifest_receipt["output_sha256"],
    )
    ack_path = tmp_path / "SESSION_CONTEXT_ACK.json"
    ack_path.write_bytes((bound / "controller" / "EXPECTED_SESSION_CONTEXT_ACK.json").read_bytes())
    verdict = session_context.verify_session_context_ack(
        bound / "SESSION_CONTEXT_CHALLENGE.json",
        ack_path,
        expected_challenge_sha256=prepare_receipt["challenge_sha256"],
    )
    verdict_path = tmp_path / "SESSION_CONTEXT_VERDICT.json"
    verdict_payload = write_json(verdict_path, verdict)
    return {
        "manifest_path": manifest_path,
        "manifest_file_sha": manifest_receipt["output_sha256"],
        "manifest": json.loads(manifest_path.read_text("utf-8")),
        "challenge_path": bound / "SESSION_CONTEXT_CHALLENGE.json",
        "challenge_sha": prepare_receipt["challenge_sha256"],
        "ack_path": ack_path,
        "ack_sha": digest(ack_path.read_bytes()),
        "verdict_path": verdict_path,
        "verdict_sha": digest(verdict_payload),
        "verdict": verdict,
    }


def make_read_only_return(tmp_path: Path, boot, work_order: Path, policy: Path, chain):
    root = tmp_path / "return"
    root.mkdir()
    boot_payload = write_json(root / "BOOT_RECEIPT.json", boot)
    proof = b"read-only audit proof\n"
    (root / "proof.txt").write_bytes(proof)
    artifacts = [
        {
            "path": name,
            "size_bytes": (root / name).stat().st_size,
            "sha256": digest((root / name).read_bytes()),
        }
        for name in sorted(["BOOT_RECEIPT.json", "proof.txt"])
    ]
    requested = {
        "live_state_apply": False,
        "push": False,
        "deploy": False,
        "external_message": False,
        "credential_rotation": False,
        "service_mutation": False,
        "scheduler_mutation": False,
        "trading": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }
    v11_envelope = {
        "schema": v11.SCHEMA_RETURN,
        "gate": gate.GATE,
        "mode": gate.MODE,
        "boot_receipt": {"path": "BOOT_RECEIPT.json", "sha256": digest(boot_payload)},
        "boot_binding": {
            "context_digest": boot["workspace"]["context_digest"],
            "r63_pointer_sha256": boot["authority"]["pointer"]["sha256"],
            "role": ROLE,
            "case_id": CASE_ID,
            "case_binding": "EXACT_STRUCTURED_MATCH",
        },
        "work_order_binding": {
            "id": CASE_ID,
            "body_sha256": digest(work_order.read_bytes()),
            "task_class": "AUDIT",
            "base_state_sha256": v11.derive_base_state_sha256(boot),
            "permission_policy_sha256": digest(policy.read_bytes()),
        },
        "terminal_state": "AUDIT_EVIDENCE_READY_FOR_REVIEW",
        "continuity_capsule": {
            "state_digest": ["Read-only audit completed."],
            "drift_risks": [],
            "unresolved": [],
            "next_action": "Controller review.",
            "stop_condition": "Do not apply state.",
        },
        "proposed_delta": [],
        "effects": {"effect_class": "REVERSIBLE", "requested": requested},
        "git": {
            "required": False,
            "bundle_artifact": None,
            "branch": None,
            "baseline_head": None,
            "baseline_tree": None,
            "final_head": None,
            "final_tree": None,
            "diff_paths": [],
        },
        "artifacts": artifacts,
        "tests": [
            {
                "name": "audit-proof",
                "result": "PASS",
                "passed": 1,
                "failed": 0,
                "skipped": 0,
                "evidence": "proof.txt",
            }
        ],
    }
    binding = {
        "session_input_manifest_file_sha256": chain["manifest_file_sha"],
        "session_input_manifest_sha256": chain["manifest"]["manifest_sha256"],
        "session_context_binding_id": chain["verdict"]["binding_id"],
        "session_context_challenge_sha256": chain["challenge_sha"],
        "session_context_ack_sha256": chain["ack_sha"],
        "session_context_verdict_sha256": chain["verdict_sha"],
        "session_context_verdict_status": "SESSION_CONTEXT_PASS",
    }
    envelope = {
        "schema": v12.SCHEMA_RETURN,
        "gate": gate.GATE,
        "mode": gate.MODE,
        "semantic_return_v1_1": v11_envelope,
        "session_context_binding": binding,
    }
    write_json(root / v12.RETURN_ENVELOPE_V12_NAME, envelope)
    return root, envelope


def setup(tmp_path: Path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, CASE_ID, control_root=control, workspace_root=workspace
    )
    work_order = tmp_path / "WORK_ORDER.md"
    work_order.write_text("# Read-only work order\n", encoding="utf-8")
    policy = tmp_path / "permission-policy.json"
    make_policy(policy)
    chain = make_session_chain(tmp_path, boot)
    candidate, envelope = make_read_only_return(
        tmp_path, boot, work_order, policy, chain
    )
    return control, workspace, work_order, policy, chain, candidate, envelope


def build_receipt(setup_values):
    control, workspace, work_order, policy, chain, candidate, _ = setup_values
    return v12.build_semantic_close_v12_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        session_input_manifest_path=chain["manifest_path"],
        expected_session_input_manifest_sha256=chain["manifest_file_sha"],
        session_context_challenge_path=chain["challenge_path"],
        expected_session_context_challenge_sha256=chain["challenge_sha"],
        session_context_ack_path=chain["ack_path"],
        session_context_verdict_path=chain["verdict_path"],
        expected_session_context_verdict_sha256=chain["verdict_sha"],
        control_root=control,
        workspace_root=workspace,
    )


def test_exact_read_only_return_passes(tmp_path):
    receipt = build_receipt(setup(tmp_path))
    assert receipt["outcome"] == "WOULD_ACCEPT"
    assert receipt["status"] == "SHADOW_ACCEPTABLE"
    assert receipt["session_context_verification"]["verified"] is True
    assert receipt["session_context_verification"]["work_order_id"] == CASE_ID
    assert receipt["semantic_v1_1_receipt"]["outcome"] == "WOULD_ACCEPT"
    assert receipt["live_state_modified"] is False


def test_tampered_verdict_holds(tmp_path):
    values = setup(tmp_path)
    chain = values[4]
    verdict = json.loads(chain["verdict_path"].read_text("utf-8"))
    verdict["checks"][0]["code"] = "MISMATCH"
    write_json(chain["verdict_path"], verdict)
    chain["verdict_sha"] = digest(chain["verdict_path"].read_bytes())
    candidate = values[5]
    envelope = json.loads((candidate / v12.RETURN_ENVELOPE_V12_NAME).read_text("utf-8"))
    envelope["session_context_binding"]["session_context_verdict_sha256"] = chain["verdict_sha"]
    write_json(candidate / v12.RETURN_ENVELOPE_V12_NAME, envelope)
    receipt = build_receipt(values)
    assert receipt["outcome"] == "WOULD_HOLD"
    assert any("VERDICT" in item or "CHECKS" in item for item in receipt["errors"])


def test_manifest_return_relation_mismatch_holds(tmp_path):
    values = setup(tmp_path)
    candidate = values[5]
    envelope = json.loads((candidate / v12.RETURN_ENVELOPE_V12_NAME).read_text("utf-8"))
    envelope["semantic_return_v1_1"]["work_order_binding"]["id"] = "OTHER-WORK"
    write_json(candidate / v12.RETURN_ENVELOPE_V12_NAME, envelope)
    receipt = build_receipt(values)
    assert receipt["outcome"] == "WOULD_HOLD"
    assert any("RELATION_MISMATCH" in item or "CASE_MISMATCH" in item for item in receipt["errors"])


def test_read_only_v12_rejects_delta_and_git(tmp_path):
    values = setup(tmp_path)
    candidate = values[5]
    envelope = json.loads((candidate / v12.RETURN_ENVELOPE_V12_NAME).read_text("utf-8"))
    envelope["semantic_return_v1_1"]["proposed_delta"] = [
        {"op": "replace", "path": "/projects/continuityos/status", "value": "changed"}
    ]
    write_json(candidate / v12.RETURN_ENVELOPE_V12_NAME, envelope)
    receipt = build_receipt(values)
    assert receipt["outcome"] == "WOULD_HOLD"
    assert any("READ_ONLY_DELTA" in item for item in receipt["errors"])


def test_wrong_pinned_challenge_holds(tmp_path):
    values = setup(tmp_path)
    control, workspace, work_order, policy, chain, candidate, _ = values
    receipt = v12.build_semantic_close_v12_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        session_input_manifest_path=chain["manifest_path"],
        expected_session_input_manifest_sha256=chain["manifest_file_sha"],
        session_context_challenge_path=chain["challenge_path"],
        expected_session_context_challenge_sha256="0" * 64,
        session_context_ack_path=chain["ack_path"],
        session_context_verdict_path=chain["verdict_path"],
        expected_session_context_verdict_sha256=chain["verdict_sha"],
        control_root=control,
        workspace_root=workspace,
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert any("PINNED_SHA256_MISMATCH" in item for item in receipt["errors"])


def test_cli_semantic_close_v12(tmp_path, capsys):
    control, workspace, work_order, policy, chain, candidate, _ = setup(tmp_path)
    code = cli.main(
        [
            "close",
            "--return",
            str(candidate),
            "--dry-run",
            "--work-order",
            str(work_order),
            "--permission-policy",
            str(policy),
            "--session-input-manifest",
            str(chain["manifest_path"]),
            "--session-input-manifest-sha256",
            chain["manifest_file_sha"],
            "--session-context-challenge",
            str(chain["challenge_path"]),
            "--session-context-challenge-sha256",
            chain["challenge_sha"],
            "--session-context-ack",
            str(chain["ack_path"]),
            "--session-context-verdict",
            str(chain["verdict_path"]),
            "--session-context-verdict-sha256",
            chain["verdict_sha"],
            "--control-root",
            str(control),
            "--workspace-root",
            str(workspace),
        ]
    )
    assert code == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["schema"] == v12.SCHEMA_CLOSE
    assert parsed["outcome"] == "WOULD_ACCEPT"


def test_packaged_v12_schemas_are_strict(tmp_path):
    values = setup(tmp_path)
    receipt = build_receipt(values)
    envelope = json.loads(
        (values[5] / v12.RETURN_ENVELOPE_V12_NAME).read_text("utf-8")
    )
    names = [
        "anti_amnesia_return_v1_2.schema.json",
        "anti_amnesia_close_receipt_v1_2.schema.json",
    ]
    schemas = [
        json.loads(resource_files("continuityos.gate.schemas").joinpath(name).read_text("utf-8"))
        for name in names
    ]
    assert all(schema["additionalProperties"] is False for schema in schemas)
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft7Validator(schemas[0]).validate(envelope)
    jsonschema.Draft7Validator(schemas[1]).validate(receipt)


def test_external_manifest_not_in_challenge_holds(tmp_path):
    values = setup(tmp_path)
    other_root = tmp_path / "other"
    other_root.mkdir()
    other_values = setup(other_root)
    control, workspace, work_order, policy, _chain, candidate, _ = values
    other_chain = other_values[4]
    envelope = json.loads((candidate / v12.RETURN_ENVELOPE_V12_NAME).read_text("utf-8"))
    envelope["session_context_binding"]["session_input_manifest_file_sha256"] = other_chain["manifest_file_sha"]
    envelope["session_context_binding"]["session_input_manifest_sha256"] = other_chain["manifest"]["manifest_sha256"]
    write_json(candidate / v12.RETURN_ENVELOPE_V12_NAME, envelope)
    receipt = v12.build_semantic_close_v12_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        session_input_manifest_path=other_chain["manifest_path"],
        expected_session_input_manifest_sha256=other_chain["manifest_file_sha"],
        session_context_challenge_path=values[4]["challenge_path"],
        expected_session_context_challenge_sha256=values[4]["challenge_sha"],
        session_context_ack_path=values[4]["ack_path"],
        session_context_verdict_path=values[4]["verdict_path"],
        expected_session_context_verdict_sha256=values[4]["verdict_sha"],
        control_root=control,
        workspace_root=workspace,
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert any("EXTERNAL_MANIFEST_MISMATCH" in item for item in receipt["errors"])


def test_implementation_task_class_is_rejected_by_read_only_v12(tmp_path):
    values = setup(tmp_path)
    candidate = values[5]
    envelope = json.loads((candidate / v12.RETURN_ENVELOPE_V12_NAME).read_text("utf-8"))
    envelope["semantic_return_v1_1"]["work_order_binding"]["task_class"] = "IMPLEMENTATION"
    write_json(candidate / v12.RETURN_ENVELOPE_V12_NAME, envelope)
    receipt = build_receipt(values)
    assert receipt["outcome"] == "WOULD_HOLD"
    assert any("READ_ONLY_TASK_CLASS" in item for item in receipt["errors"])
