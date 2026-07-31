from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

import pytest

from continuityos.gate import anti_amnesia as gate
from continuityos.gate import cli
from continuityos.gate import semantic_close as semantic


ROLE = "CODEX-01"
CASE_ID = "WO-SEMANTIC-001"

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


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def write_json(path: Path, value) -> bytes:
    payload = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return payload


def descriptor(path: str, payload: bytes):
    return {"path": path, "size_bytes": len(payload), "sha256": digest(payload)}


def make_control_root(tmp_path: Path, *, case_id=CASE_ID) -> Path:
    root = tmp_path / "control"
    root.mkdir()
    role_record = {"state": "READY", "lane": "ContinuityOS", "case_id": case_id}
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
        payload = write_json(root / logical, document)
        descriptors[name] = descriptor(logical, payload)
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
        [
            {
                "id": "loop-1",
                "title": "Review semantic close",
                "status": "open",
                "next_action": "Review receipt",
            }
        ],
    )
    (root / "01_RUNTIME" / "checkpoints.jsonl").write_bytes(
        canonical_bytes({"checkpoint_id": "cp-1"}) + b"\n"
    )
    return root


def git_output(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def make_git_bundle(tmp_path: Path):
    repo = tmp_path / "source_repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "candidate"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    (repo / "continuityos").mkdir()
    (repo / "continuityos" / "base.py").write_text("BASE = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo, check=True, capture_output=True)
    baseline_head = git_output(repo, "rev-parse", "HEAD")
    baseline_tree = git_output(repo, "rev-parse", "HEAD^{tree}")
    (repo / "continuityos" / "feature.py").write_text("FEATURE = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "feature"], cwd=repo, check=True, capture_output=True)
    final_head = git_output(repo, "rev-parse", "HEAD")
    final_tree = git_output(repo, "rev-parse", "HEAD^{tree}")
    bundle = tmp_path / "candidate.bundle"
    subprocess.run(["git", "bundle", "create", str(bundle), "candidate"], cwd=repo, check=True)
    diff_paths = [
        {"status": "A", "path": "continuityos/feature.py", "old_path": None}
    ]
    return bundle, baseline_head, baseline_tree, final_head, final_tree, diff_paths


def make_policy(path: Path, *, allow_no_case=False, git_paths=None, delta_prefixes=None, effects=None):
    policy = {
        "schema": semantic.SCHEMA_POLICY,
        "authority_generation": "R63",
        "policy_id": "test-policy",
        "roles": {
            ROLE: {
                "allow_no_case": allow_no_case,
                "allowed_delta_prefixes": sorted(delta_prefixes or ["/projects/continuityos"]),
                "allowed_git_paths": sorted(git_paths or ["continuityos/"]),
                "allowed_effect_classes": sorted(effects or ["REVERSIBLE"]),
            }
        },
    }
    path.write_bytes(canonical_bytes(policy))
    return policy


def make_semantic_return(
    tmp_path: Path,
    boot,
    work_order_path: Path,
    policy_path: Path,
    *,
    delta_path="/projects/continuityos/status",
    effect_class="REVERSIBLE",
    requested_overrides=None,
    git_path_override=None,
):
    root = tmp_path / "return"
    root.mkdir()
    boot_payload = canonical_bytes(boot)
    (root / "BOOT_RECEIPT.json").write_bytes(boot_payload)
    proof = b"proof\n"
    (root / "proof.txt").write_bytes(proof)
    bundle, baseline_head, baseline_tree, final_head, final_tree, diff_paths = make_git_bundle(tmp_path)
    bundle_name = "candidate.bundle"
    (root / bundle_name).write_bytes(bundle.read_bytes())
    if git_path_override is not None:
        diff_paths = [{"status": "A", "path": git_path_override, "old_path": None}]
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
    requested.update(requested_overrides or {})
    envelope = {
        "schema": semantic.SCHEMA_RETURN,
        "gate": gate.GATE,
        "mode": gate.MODE,
        "boot_receipt": {"path": "BOOT_RECEIPT.json", "sha256": digest(boot_payload)},
        "boot_binding": {
            "context_digest": boot["workspace"]["context_digest"],
            "r63_pointer_sha256": boot["authority"]["pointer"]["sha256"],
            "role": ROLE,
            "case_id": boot["command"]["case_id"],
            "case_binding": boot["binding"]["case"]["status"],
        },
        "work_order_binding": {
            "id": boot["command"]["case_id"] or "NO-CASE-WORK",
            "body_sha256": digest(work_order_path.read_bytes()),
            "task_class": "IMPLEMENTATION",
            "base_state_sha256": semantic.derive_base_state_sha256(boot),
            "permission_policy_sha256": digest(policy_path.read_bytes()),
        },
        "terminal_state": "IMPLEMENTATION_READY_FOR_REVIEW",
        "continuity_capsule": {
            "state_digest": ["Semantic close candidate prepared."],
            "drift_risks": [],
            "unresolved": [],
            "next_action": "Controller review.",
            "stop_condition": "Do not apply state in shadow mode.",
        },
        "proposed_delta": [
            {"op": "replace", "path": delta_path, "value": "candidate"}
        ],
        "effects": {"effect_class": effect_class, "requested": requested},
        "git": {
            "required": True,
            "bundle_artifact": bundle_name,
            "branch": "candidate",
            "baseline_head": baseline_head,
            "baseline_tree": baseline_tree,
            "final_head": final_head,
            "final_tree": final_tree,
            "diff_paths": diff_paths,
        },
        "artifacts": [],
        "tests": [
            {
                "name": "unit",
                "result": "PASS",
                "passed": 1,
                "failed": 0,
                "skipped": 0,
                "evidence": "proof.txt",
            }
        ],
    }
    names = ["BOOT_RECEIPT.json", "candidate.bundle", "proof.txt"]
    envelope["artifacts"] = [
        {
            "path": name,
            "size_bytes": (root / name).stat().st_size,
            "sha256": digest((root / name).read_bytes()),
        }
        for name in sorted(names)
    ]
    write_json(root / semantic.RETURN_ENVELOPE_V11_NAME, envelope)
    return root


def setup_case(tmp_path: Path, *, with_case=True, allow_no_case=False, policy_git_paths=None, policy_delta_prefixes=None, policy_effects=None):
    case = CASE_ID if with_case else None
    control = make_control_root(tmp_path, case_id=case)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(ROLE, case, control_root=control, workspace_root=workspace)
    work_order = tmp_path / "WORK_ORDER.md"
    work_order.write_text("# Work order\n", encoding="utf-8")
    policy = tmp_path / "permission-policy.json"
    make_policy(
        policy,
        allow_no_case=allow_no_case,
        git_paths=policy_git_paths,
        delta_prefixes=policy_delta_prefixes,
        effects=policy_effects,
    )
    return control, workspace, boot, work_order, policy


def test_semantic_close_accepts_exact_bound_implementation(tmp_path):
    control, workspace, boot, work_order, policy = setup_case(tmp_path)
    candidate = make_semantic_return(tmp_path, boot, work_order, policy)
    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )
    assert receipt["outcome"] == "WOULD_ACCEPT"
    assert receipt["status"] == "SHADOW_ACCEPTABLE"
    assert receipt["git_verification"]["verified"] is True
    assert receipt["delta_verification"] == {
        "count": 1,
        "paths": ["/projects/continuityos/status"],
        "permitted": True,
    }
    assert receipt["approval"]["required"] is False
    assert receipt["live_state_modified"] is False


def test_semantic_close_wrong_work_order_hash_holds(tmp_path):
    control, workspace, boot, work_order, policy = setup_case(tmp_path)
    candidate = make_semantic_return(tmp_path, boot, work_order, policy)
    work_order.write_text("changed\n", encoding="utf-8")
    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "SEMANTIC_BINDING_MISMATCH" in receipt["errors"]


def test_semantic_close_delta_scope_violation_holds(tmp_path):
    control, workspace, boot, work_order, policy = setup_case(tmp_path)
    candidate = make_semantic_return(
        tmp_path,
        boot,
        work_order,
        policy,
        delta_path="/security/authority",
    )
    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert any("ROLE_SCOPE_VIOLATION" in item for item in receipt["errors"])


def test_semantic_close_git_path_violation_holds(tmp_path):
    control, workspace, boot, work_order, policy = setup_case(tmp_path)
    candidate = make_semantic_return(
        tmp_path,
        boot,
        work_order,
        policy,
        git_path_override="outside.txt",
    )
    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert any("DIFF_INVENTORY_MISMATCH" in item or "ROLE_PATH_VIOLATION" in item for item in receipt["errors"])


def test_semantic_close_compensatable_requires_human_approval(tmp_path):
    control, workspace, boot, work_order, policy = setup_case(
        tmp_path,
        policy_effects=["COMPENSATABLE", "REVERSIBLE"],
    )
    candidate = make_semantic_return(
        tmp_path,
        boot,
        work_order,
        policy,
        effect_class="COMPENSATABLE",
        requested_overrides={"push": True},
    )
    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )
    assert receipt["outcome"] == "PENDING_HUMAN_APPROVAL"
    assert receipt["approval"]["required"] is True
    assert "EFFECT_CLASS_COMPENSATABLE" in receipt["approval"]["reasons"]
    assert "PUSH" in receipt["approval"]["reasons"]
    assert receipt["live_state_modified"] is False


def test_semantic_close_no_case_denied_by_policy(tmp_path):
    control, workspace, boot, work_order, policy = setup_case(
        tmp_path,
        with_case=False,
        allow_no_case=False,
    )
    candidate = make_semantic_return(tmp_path, boot, work_order, policy)
    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "permission_policy:NO_CASE_NOT_AUTHORIZED" in receipt["errors"]


def test_semantic_close_no_case_allowed_by_policy(tmp_path):
    control, workspace, boot, work_order, policy = setup_case(
        tmp_path,
        with_case=False,
        allow_no_case=True,
    )
    candidate = make_semantic_return(tmp_path, boot, work_order, policy)
    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )
    assert receipt["outcome"] == "WOULD_ACCEPT"


def test_workflow_triggers_gpt_review_branches():
    workflow = Path(".github/workflows/ci.yml").read_text("utf-8")
    assert '"gpt/**"' in workflow



def test_semantic_close_rejects_missing_test_evidence_artifact(tmp_path):
    control, workspace, boot, work_order, policy = setup_case(tmp_path)
    candidate = make_semantic_return(tmp_path, boot, work_order, policy)
    envelope_path = candidate / semantic.RETURN_ENVELOPE_V11_NAME
    envelope = json.loads(envelope_path.read_text("utf-8"))
    envelope["tests"][0]["evidence"] = "missing.txt"
    write_json(envelope_path, envelope)

    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )

    assert receipt["outcome"] == "WOULD_HOLD"
    assert "RETURN_TEST_EVIDENCE_MISSING:missing.txt" in receipt["errors"]


def test_semantic_close_rejects_incoherent_test_tally(tmp_path):
    control, workspace, boot, work_order, policy = setup_case(tmp_path)
    candidate = make_semantic_return(tmp_path, boot, work_order, policy)
    envelope_path = candidate / semantic.RETURN_ENVELOPE_V11_NAME
    envelope = json.loads(envelope_path.read_text("utf-8"))
    envelope["tests"][0]["failed"] = 1
    write_json(envelope_path, envelope)

    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )

    assert receipt["outcome"] == "WOULD_HOLD"
    assert "return.tests[0]:INCOHERENT_PASS_TALLY" in receipt["errors"]


def test_semantic_close_manual_validator_rejects_mutated_delta_count(tmp_path):
    control, workspace, boot, work_order, policy = setup_case(tmp_path)
    candidate = make_semantic_return(tmp_path, boot, work_order, policy)
    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )
    mutated = copy.deepcopy(receipt)
    mutated["delta_verification"]["count"] = 2
    with pytest.raises(semantic.SemanticCloseError):
        semantic.validate_semantic_close_receipt(mutated)


def test_cli_semantic_close_emits_v1_1_receipt(tmp_path, capsys):
    control, workspace, boot, work_order, policy = setup_case(tmp_path)
    candidate = make_semantic_return(tmp_path, boot, work_order, policy)

    exit_code = cli.main([
        "close",
        "--return", str(candidate),
        "--dry-run",
        "--work-order", str(work_order),
        "--permission-policy", str(policy),
        "--control-root", str(control),
        "--workspace-root", str(workspace),
    ])
    receipt = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert receipt["schema"] == semantic.SCHEMA_CLOSE
    assert receipt["outcome"] == "WOULD_ACCEPT"


@pytest.mark.filterwarnings("ignore:jsonschema.RefResolver is deprecated")
def test_semantic_return_and_close_match_published_schemas(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    control, workspace, boot, work_order, policy = setup_case(tmp_path)
    candidate = make_semantic_return(tmp_path, boot, work_order, policy)
    envelope = json.loads(
        (candidate / semantic.RETURN_ENVELOPE_V11_NAME).read_text("utf-8")
    )
    receipt = semantic.build_semantic_close_receipt(
        candidate,
        True,
        work_order_path=work_order,
        permission_policy_path=policy,
        control_root=control,
        workspace_root=workspace,
    )
    schema_root = Path(gate.__file__).parent / "schemas"
    for name, instance in (
        ("anti_amnesia_return_v1_1.schema.json", envelope),
        ("anti_amnesia_close_receipt_v1_1.schema.json", receipt),
        ("anti_amnesia_role_permission_policy_v1.schema.json", json.loads(policy.read_text("utf-8"))),
    ):
        schema = json.loads((schema_root / name).read_text("utf-8"))
        resolver = jsonschema.RefResolver(
            base_uri=schema_root.as_uri() + "/",
            referrer=schema,
        )
        jsonschema.Draft7Validator(
            schema, resolver=resolver
        ).validate(instance)
