from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from continuityos.gate import anti_amnesia as gate
from continuityos.gate import cli


ROLE = "CODEX-01"

POINTER_EFFECT = {
    "auto_dispatch": False,
    "auto_accept": False,
    "push": "DENY",
    "deploy": "DENY",
    "can_trade": False,
    "capital_permission": "DENY",
}

GLOBAL_EFFECT = {
    **POINTER_EFFECT,
    "self_application": False,
}


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


def file_descriptor(path: str, payload: bytes):
    return {
        "path": path,
        "size_bytes": len(payload),
        "sha256": digest(payload),
    }


def make_control_root(
    tmp_path: Path,
    *,
    case_id=None,
    readback_required=False,
) -> Path:
    root = tmp_path / "control"
    root.mkdir()
    role_record = {"state": "READY", "lane": "ContinuityOS"}
    if case_id is not None:
        role_record["case_id"] = case_id

    documents = {
        "manifest": (
            "MANIFEST.json",
            {"schema": "CONTROL_ROOT_MANIFEST_R63"},
        ),
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
                    ROLE: {
                        "path": "ROLE_VIEWS.json",
                        "json_pointer": f"/roles/{ROLE}",
                    }
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
        "packet_manifest": (
            "R63/MANIFEST.json",
            {"schema": "CONTROL_PACKET_MANIFEST_R63"},
        ),
    }

    descriptors = {}
    for name, (logical, document) in documents.items():
        payload = write_json(root / logical, document)
        descriptors[name] = file_descriptor(logical, payload)

    ready_protocol = {"marker": "R63/READY.json"}
    if readback_required:
        ready_protocol["raw_provider_readback_required"] = True
    pointer = {
        "schema": "CONTROL_CURRENT_POINTER_R63",
        "generation": "R63",
        **descriptors,
        "ready_protocol": ready_protocol,
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
            "status": "R63_WRITTEN_LOCAL_DRIVEFS_READBACK_PENDING",
            "can_trade": False,
            "capital_permission": "DENY",
        },
    )
    return root


def make_workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    canon = root / "00_CANON"
    runtime = root / "01_RUNTIME"
    canon.mkdir(parents=True)
    runtime.mkdir()
    (canon / "HUMAN_CANON.md").write_text("# Human\n", encoding="utf-8")
    (canon / "INVARIANTS.md").write_text("# Invariants\n", encoding="utf-8")
    (canon / "INTERNAL_AGENTS.md").write_text("# Agents\n", encoding="utf-8")
    write_json(runtime / "state.json", {"last_checkpoint_id": "cp-0001"})
    write_json(runtime / "projects.json", {"continuity": {"status": "active"}})
    write_json(
        runtime / "open_loops.json",
        [
            {
                "id": "ol-1",
                "title": "Human review",
                "status": "open",
                "next_action": "Review shadow receipt.",
            },
            {
                "id": "ol-2",
                "title": "Closed",
                "status": "closed",
                "next_action": None,
            },
        ],
    )
    (runtime / "checkpoints.jsonl").write_bytes(
        canonical_bytes({"checkpoint_id": "cp-0001"}) + b"\n"
    )
    return root


def rewrite_control_document(root: Path, descriptor_name: str, document) -> None:
    pointer_path = root / "CURRENT_POINTER.json"
    pointer = json.loads(pointer_path.read_text("utf-8"))
    logical = pointer[descriptor_name]["path"]
    payload = write_json(root / logical, document)
    pointer[descriptor_name] = file_descriptor(logical, payload)
    pointer_payload = write_json(pointer_path, pointer)
    ready_path = root / pointer["ready_protocol"]["marker"]
    ready = json.loads(ready_path.read_text("utf-8"))
    ready["pointer_sha256"] = digest(pointer_payload)
    ready["pointer_size_bytes"] = len(pointer_payload)
    write_json(ready_path, ready)


def tree_snapshot(root: Path):
    return {
        item.relative_to(root).as_posix(): digest(item.read_bytes())
        for item in sorted(root.rglob("*"))
        if item.is_file()
    }


def recompute_workspace_context(workspace):
    digest_input = {
        "files": workspace["files"],
        "latest_checkpoint_id": workspace["latest_checkpoint_id"],
        "project_count": workspace["project_count"],
        "open_loop_count": workspace["open_loop_count"],
        "active_open_loop_ids": workspace["active_open_loop_ids"],
        "active_open_loops": workspace["active_open_loops"],
        "active_open_loops_digest": workspace[
            "active_open_loops_digest"
        ],
    }
    workspace["context_digest"] = gate.sha256_canonical(digest_input)


def make_return_directory(
    tmp_path: Path,
    boot_receipt,
    *,
    effects_override=None,
) -> Path:
    root = tmp_path / "return"
    root.mkdir()
    boot_payload = canonical_bytes(boot_receipt)
    (root / "BOOT_RECEIPT.json").write_bytes(boot_payload)
    artifact = b"proof\n"
    (root / "proof.txt").write_bytes(artifact)
    effects = {
        "live_state_applied": False,
        "r63_authority_replaced": False,
        "return_registry_mutated": False,
        "checkpoint_created": False,
        "push": False,
        "deploy": False,
        "external_messages": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }
    effects.update(effects_override or {})
    envelope = {
        "schema": "ANTI_AMNESIA_RETURN_V1",
        "gate": "ANTI_AMNESIA_GATE_V1",
        "mode": "SHADOW",
        "boot_receipt": {
            "path": "BOOT_RECEIPT.json",
            "sha256": digest(boot_payload),
        },
        "boot_binding": {
            "context_digest": boot_receipt["workspace"]["context_digest"],
            "r63_pointer_sha256": boot_receipt["authority"]["pointer"]["sha256"],
            "role": ROLE,
            "case_id": boot_receipt["command"]["case_id"],
            "case_binding": boot_receipt["binding"]["case"]["status"],
        },
        "terminal_state": "HUMAN_GATE_READY",
        "continuity_capsule": {
            "state_digest": ["R63 remains authoritative."],
            "drift_risks": [],
            "top_open_loops": [
                {
                    "id": "ol-1",
                    "title": "Human review",
                    "status": "open",
                    "next_action": "Review shadow receipt.",
                }
            ],
            "next_irreversible_action": "Explicit human adoption decision.",
            "checkpoint_delta": {
                "action": "NONE",
                "reference": None,
                "reason": "Shadow close cannot create checkpoints.",
            },
        },
        "work_delta": {
            "summary": "Validated a shadow return candidate.",
            "state_changes": [],
            "source_changes": [],
            "unknowns": [],
        },
        "product_delta": {
            "status": "ZERO",
            "evidence": ["No product state was applied."],
        },
        "effects": effects,
        "artifacts": [
            {
                "path": "BOOT_RECEIPT.json",
                "size_bytes": len(boot_payload),
                "sha256": digest(boot_payload),
            },
            {
                "path": "proof.txt",
                "size_bytes": len(artifact),
                "sha256": digest(artifact),
            }
        ],
        "tests": [
            {
                "name": "shadow-contract",
                "result": "PASS",
                "passed": 1,
                "failed": 0,
                "skipped": 0,
                "evidence": "proof.txt",
            }
        ],
    }
    write_json(root / gate.RETURN_ENVELOPE_NAME, envelope)
    return root


def make_zip(source: Path, destination: Path) -> Path:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            info = zipfile.ZipInfo(path.relative_to(source).as_posix())
            info.date_time = (2020, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    return destination


def check_codes(receipt):
    return {row["code"] for row in receipt["checks"]}


def test_boot_is_deterministic_and_read_only(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    before_control = tree_snapshot(control)
    before_workspace = tree_snapshot(workspace)

    first = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    second = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )

    assert first["outcome"] == "WOULD_ALLOW"
    assert first["status"] == "SHADOW_READY"
    assert first["authority"]["generation"] == "R63"
    assert first["authority"]["relation"] == (
        "ADVISORY_ONLY_R63_REMAINS_AUTHORITATIVE"
    )
    assert first["binding"]["role"]["authority_status"] == "EXACT_R63_ROLE"
    assert first["binding"]["case"]["status"] == "NOT_REQUESTED"
    assert gate.canonical_json_bytes(first) == gate.canonical_json_bytes(second)
    assert tree_snapshot(control) == before_control
    assert tree_snapshot(workspace) == before_workspace
    assert not (workspace / "01_RUNTIME" / ".runtime.lock").exists()
    assert not (workspace / "01_RUNTIME" / ".runtime_txn.json").exists()


def test_boot_two_pass_snapshot_change_holds(tmp_path, monkeypatch):
    control = make_control_root(tmp_path)
    workspace_root = make_workspace(tmp_path)
    original_bind = gate.bind_workspace
    calls = 0

    def unstable_bind(root=None):
        nonlocal calls
        calls += 1
        workspace, docs, checks, errors, warnings = original_bind(root)
        if calls == 2:
            workspace = copy.deepcopy(workspace)
            workspace["project_count"] += 1
            recompute_workspace_context(workspace)
        return workspace, docs, checks, errors, warnings

    monkeypatch.setattr(gate, "bind_workspace", unstable_bind)
    receipt = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace_root
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "BOOT_INPUT_SNAPSHOT_CHANGED" in receipt["errors"]


def test_case_without_structured_r63_field_holds(tmp_path):
    receipt = gate.build_boot_receipt(
        ROLE,
        "CASE-7",
        control_root=make_control_root(tmp_path),
        workspace_root=make_workspace(tmp_path),
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert receipt["binding"]["case"] == {
        "requested": "CASE-7",
        "status": "CLI_ASSERTED_NON_AUTHORITY",
        "authoritative": False,
        "matched_field": None,
    }
    assert "CASE_NOT_STRUCTURED_IN_R63" in receipt["errors"]


def test_exact_structured_case_match(tmp_path):
    receipt = gate.build_boot_receipt(
        ROLE,
        "CASE-7",
        control_root=make_control_root(tmp_path, case_id="CASE-7"),
        workspace_root=make_workspace(tmp_path),
    )
    assert receipt["outcome"] == "WOULD_ALLOW"
    assert receipt["binding"]["case"]["status"] == "EXACT_STRUCTURED_MATCH"
    assert receipt["binding"]["case"]["authoritative"] is True


def test_required_provider_readback_is_explicit_shadow_warning(tmp_path):
    receipt = gate.build_boot_receipt(
        ROLE,
        control_root=make_control_root(tmp_path, readback_required=True),
        workspace_root=make_workspace(tmp_path),
    )
    assert receipt["outcome"] == "WOULD_ALLOW_WITH_WARNINGS"
    assert (
        "R63_RAW_PROVIDER_READBACK_OUTSIDE_SHADOW_PROOF"
        in receipt["warnings"]
    )


@pytest.mark.parametrize("role", ["codex-01", "", "A" * 65])
def test_invalid_role_holds_without_throwing(tmp_path, role):
    receipt = gate.build_boot_receipt(
        role,
        control_root=make_control_root(tmp_path),
        workspace_root=make_workspace(tmp_path),
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "INVALID_ROLE_ID" in receipt["errors"]


def test_overlong_invalid_arguments_still_produce_schema_valid_hold(tmp_path):
    receipt = gate.build_boot_receipt(
        "R" * 4096,
        "C" * 4096,
        control_root=make_control_root(tmp_path),
        workspace_root=make_workspace(tmp_path),
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    gate.validate_boot_receipt(receipt)


def test_pointer_hash_mismatch_holds(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    (control / "ROLE_VIEWS.json").write_bytes(b"{}")
    receipt = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "R63_DESCRIPTOR_MISMATCH:role_views" in receipt["errors"]


def test_r63_document_schema_mismatch_holds(tmp_path):
    control = make_control_root(tmp_path)
    pointer = json.loads((control / "CURRENT_POINTER.json").read_text("utf-8"))
    path = control / pointer["role_views"]["path"]
    document = json.loads(path.read_text("utf-8"))
    document["schema"] = "CONTROL_ROLE_VIEWS_R62"
    rewrite_control_document(control, "role_views", document)

    receipt = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=make_workspace(tmp_path)
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert (
        "R63_DOCUMENT_CONTRACT_MISMATCH:role_views" in receipt["errors"]
    )


def test_role_index_cannot_cross_bind_another_role(tmp_path):
    control = make_control_root(tmp_path)
    pointer = json.loads((control / "CURRENT_POINTER.json").read_text("utf-8"))
    views_path = control / pointer["role_views"]["path"]
    views = json.loads(views_path.read_text("utf-8"))
    views["roles"]["OTHER"] = {"state": "READY", "lane": "Other"}
    rewrite_control_document(control, "role_views", views)
    pointer = json.loads((control / "CURRENT_POINTER.json").read_text("utf-8"))
    index_path = control / pointer["role_index"]["path"]
    index = json.loads(index_path.read_text("utf-8"))
    index["role_views"][ROLE]["json_pointer"] = "/roles/OTHER"
    rewrite_control_document(control, "role_index", index)

    receipt = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=make_workspace(tmp_path)
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "ROLE_JSON_POINTER_IDENTITY_MISMATCH" in receipt["errors"]


def test_state_checkpoint_mismatch_holds(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    write_json(
        workspace / "01_RUNTIME" / "state.json",
        {"last_checkpoint_id": "cp-stale"},
    )
    receipt = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "STATE_CHECKPOINT_ID_MISMATCH" in receipt["errors"]


def test_parseable_but_invalid_open_loop_shape_holds(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    write_json(
        workspace / "01_RUNTIME" / "open_loops.json",
        {"ol-1": {"status": "open"}},
    )
    receipt = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "OPEN_LOOPS_MINIMAL_CONTRACT_MISMATCH" in receipt["errors"]


def test_duplicate_live_loop_ids_hold_instead_of_collapsing(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    loops_path = workspace / "01_RUNTIME" / "open_loops.json"
    loops = json.loads(loops_path.read_text("utf-8"))
    duplicate = dict(loops[0])
    duplicate["title"] = "Duplicate identity"
    loops.append(duplicate)
    write_json(loops_path, loops)
    receipt = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "OPEN_LOOPS_DUPLICATE_ID" in receipt["errors"]


def test_pending_transaction_journal_is_hold_and_is_not_replayed(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    journal = workspace / "01_RUNTIME" / ".runtime_txn.json"
    original = b'{"do_not_replay":true}'
    journal.write_bytes(original)
    before = tree_snapshot(workspace)
    receipt = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert receipt["workspace"]["transaction_journal_present"] is True
    assert "LIVE_TRANSACTION_JOURNAL_PRESENT" in receipt["errors"]
    assert journal.read_bytes() == original
    assert tree_snapshot(workspace) == before


def test_valid_directory_close_is_deterministic_and_non_applying(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    before = tree_snapshot(candidate)

    first = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    second = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )

    assert first["outcome"] == "WOULD_ACCEPT"
    assert first["status"] == "SHADOW_ACCEPTABLE"
    assert first["closed"] is False
    assert first["live_state_modified"] is False
    assert first["candidate"]["kind"] == "DIRECTORY"
    assert gate.canonical_json_bytes(first) == gate.canonical_json_bytes(second)
    assert tree_snapshot(candidate) == before


def test_directory_close_detects_same_name_second_pass_change(
    tmp_path, monkeypatch
):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    proof = candidate / "proof.txt"
    original_stable_read = gate.stable_read_bytes

    def changing_read(path, *, label, max_bytes=gate.MAX_INPUT_FILE_BYTES):
        if label == "return.recheck.proof.txt":
            proof.write_bytes(b"changed after first full pass\n")
        return original_stable_read(path, label=label, max_bytes=max_bytes)

    monkeypatch.setattr(gate, "stable_read_bytes", changing_read)
    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "RETURN_DIRECTORY_CHANGED_DURING_READ" in receipt["errors"]


def test_valid_zip_close_never_extracts(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    archive = make_zip(candidate, tmp_path / "return.zip")
    before = set(tmp_path.rglob("*"))

    receipt = gate.build_close_receipt(
        archive, True, control_root=control, workspace_root=workspace
    )

    assert receipt["outcome"] == "WOULD_ACCEPT"
    assert receipt["candidate"]["kind"] == "ZIP"
    assert set(tmp_path.rglob("*")) == before


@pytest.mark.parametrize("kind", ["directory", "zip"])
def test_empty_return_candidate_holds(tmp_path, kind):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    candidate = tmp_path / ("empty" if kind == "directory" else "empty.zip")
    if kind == "directory":
        candidate.mkdir()
    else:
        with zipfile.ZipFile(candidate, "w"):
            pass
    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "RETURN_ENVELOPE_MISSING" in receipt["errors"]


def test_close_requires_actual_boot_receipt_binding(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    envelope_path = candidate / gate.RETURN_ENVELOPE_NAME
    envelope = json.loads(envelope_path.read_text("utf-8"))
    envelope["boot_binding"]["case_binding"] = "CLI_ASSERTED_NON_AUTHORITY"
    write_json(envelope_path, envelope)

    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "BOOT_RECEIPT_DECLARATION_MISMATCH" in receipt["errors"]


def test_close_requires_complete_boot_open_loop_set(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    envelope_path = candidate / gate.RETURN_ENVELOPE_NAME
    envelope = json.loads(envelope_path.read_text("utf-8"))
    envelope["continuity_capsule"]["top_open_loops"] = []
    write_json(envelope_path, envelope)
    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "RETURN_OPEN_LOOP_SET_MISMATCH" in receipt["errors"]


def test_close_rejects_open_loop_semantic_substitution(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    envelope_path = candidate / gate.RETURN_ENVELOPE_NAME
    envelope = json.loads(envelope_path.read_text("utf-8"))
    envelope["continuity_capsule"]["top_open_loops"][0][
        "title"
    ] = "Rewritten meaning"
    write_json(envelope_path, envelope)
    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "RETURN_OPEN_LOOP_SEMANTICS_MISMATCH" in receipt["errors"]


def test_close_rederives_exact_case_from_current_role_record(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    forged_boot = copy.deepcopy(boot)
    forged_boot["command"]["case_id"] = "FORGED-CASE"
    forged_boot["binding"]["case"] = {
        "requested": "FORGED-CASE",
        "status": "EXACT_STRUCTURED_MATCH",
        "authoritative": True,
        "matched_field": "case_id",
    }
    gate.validate_boot_receipt(forged_boot)
    candidate = make_return_directory(tmp_path, boot)
    boot_path = candidate / "BOOT_RECEIPT.json"
    forged_payload = canonical_bytes(forged_boot)
    boot_path.write_bytes(forged_payload)
    envelope_path = candidate / gate.RETURN_ENVELOPE_NAME
    envelope = json.loads(envelope_path.read_text("utf-8"))
    envelope["boot_receipt"]["sha256"] = digest(forged_payload)
    envelope["boot_binding"]["case_id"] = "FORGED-CASE"
    envelope["boot_binding"]["case_binding"] = "EXACT_STRUCTURED_MATCH"
    for artifact in envelope["artifacts"]:
        if artifact["path"] == "BOOT_RECEIPT.json":
            artifact["size_bytes"] = len(forged_payload)
            artifact["sha256"] = digest(forged_payload)
    write_json(envelope_path, envelope)

    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "BOOT_RECEIPT_CASE_BINDING_NOT_CURRENT" in receipt["errors"]


def test_close_requires_exact_current_boot_authority_object(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    forged_boot = copy.deepcopy(boot)
    forged_boot["authority"]["descriptors"][0]["sha256"] = "0" * 64
    gate.validate_boot_receipt(forged_boot)
    candidate = make_return_directory(tmp_path, forged_boot)
    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "BOOT_RECEIPT_AUTHORITY_STALE" in receipt["errors"]


def test_close_requires_whole_current_boot_receipt(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    forged_boot = copy.deepcopy(boot)
    forged_boot["binding"]["role"]["state"] = "FORGED"
    gate.validate_boot_receipt(forged_boot)
    candidate = make_return_directory(tmp_path, forged_boot)
    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "BOOT_RECEIPT_NOT_CURRENT_EXACT" in receipt["errors"]


def test_close_rebind_detects_decision_window_change(tmp_path, monkeypatch):
    control = make_control_root(tmp_path)
    workspace_root = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace_root
    )
    candidate = make_return_directory(tmp_path, boot)
    original_bind = gate.bind_workspace
    calls = 0

    def changed_after_candidate(root=None):
        nonlocal calls
        calls += 1
        workspace, docs, checks, errors, warnings = original_bind(root)
        if calls >= 2:
            workspace = copy.deepcopy(workspace)
            workspace["project_count"] += 1
            recompute_workspace_context(workspace)
        return workspace, docs, checks, errors, warnings

    monkeypatch.setattr(gate, "bind_workspace", changed_after_candidate)
    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace_root
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "CLOSE_INPUT_SNAPSHOT_CHANGED" in receipt["errors"]


def test_failed_test_is_preserved_as_acceptance_warning(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    envelope_path = candidate / gate.RETURN_ENVELOPE_NAME
    envelope = json.loads(envelope_path.read_text("utf-8"))
    envelope["tests"].append(
        {
            "name": "technical-regression",
            "result": "FAIL",
            "passed": 0,
            "failed": 1,
            "skipped": 0,
            "evidence": "proof.txt",
        }
    )
    write_json(envelope_path, envelope)
    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_ACCEPT_WITH_WARNINGS"
    assert "RETURN_CONTAINS_FAILED_TESTS" in receipt["warnings"]


def test_skip_only_return_is_not_technical_evidence(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    envelope_path = candidate / gate.RETURN_ENVELOPE_NAME
    envelope = json.loads(envelope_path.read_text("utf-8"))
    envelope["tests"] = [
        {
            "name": "not-run",
            "result": "SKIP",
            "passed": 0,
            "failed": 0,
            "skipped": 1,
            "evidence": None,
        }
    ]
    write_json(envelope_path, envelope)
    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "return:NO_EVIDENCED_PASS" in receipt["errors"]


def test_close_rejects_effect_claim(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(
        tmp_path, boot, effects_override={"can_trade": True}
    )
    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert any("EXPECTED_FALSE" in code for code in receipt["errors"])


def test_close_rejects_stale_boot_binding(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    state_path = workspace / "01_RUNTIME" / "state.json"
    state = json.loads(state_path.read_text("utf-8"))
    state["shadow_only_change"] = True
    write_json(state_path, state)

    receipt = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "RETURN_BOOT_BINDING_STALE" in receipt["errors"]


def test_zip_traversal_is_rejected(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../escape.txt", b"no")
    receipt = gate.build_close_receipt(
        archive, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "RETURN_UNSAFE_PATH" in receipt["errors"]
    assert not (tmp_path.parent / "escape.txt").exists()


@pytest.mark.parametrize("unsafe_name", ["dir/file:stream", "NUL.txt"])
def test_zip_downstream_windows_hazards_are_rejected(tmp_path, unsafe_name):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    archive = tmp_path / "unsafe-windows.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(unsafe_name, b"no")
    receipt = gate.build_close_receipt(
        archive, True, control_root=control, workspace_root=workspace
    )
    assert receipt["outcome"] == "WOULD_HOLD"
    assert "RETURN_UNSAFE_PATH" in receipt["errors"]


def test_return_validator_rejects_incoherent_test_tally(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    path = candidate / gate.RETURN_ENVELOPE_NAME
    envelope = json.loads(path.read_text("utf-8"))
    envelope["tests"][0]["failed"] = 1
    with pytest.raises(gate.AntiAmnesiaError, match="PASS_TALLY_MISMATCH"):
        gate.validate_return_envelope(envelope)


def test_manual_receipt_validators_reject_effect_mutation(tmp_path):
    boot = gate.build_boot_receipt(
        ROLE,
        control_root=make_control_root(tmp_path),
        workspace_root=make_workspace(tmp_path),
    )
    mutated = copy.deepcopy(boot)
    mutated["can_trade"] = True
    with pytest.raises(gate.AntiAmnesiaError, match="EXPECTED_FALSE"):
        gate.validate_boot_receipt(mutated)


def test_manual_validator_derives_diagnostics_and_ready_authority(tmp_path):
    boot = gate.build_boot_receipt(
        ROLE,
        control_root=make_control_root(tmp_path),
        workspace_root=make_workspace(tmp_path),
    )
    inconsistent = copy.deepcopy(boot)
    inconsistent["checks"][0]["status"] = "FAIL"
    with pytest.raises(gate.AntiAmnesiaError, match="ERROR_DERIVATION"):
        gate.validate_boot_receipt(inconsistent)

    wrong_generation = copy.deepcopy(boot)
    wrong_generation["authority"]["generation"] = "R62"
    with pytest.raises(gate.AntiAmnesiaError, match="UNVERIFIED_AUTHORITY"):
        gate.validate_boot_receipt(wrong_generation)


def test_manual_boot_validator_recomputes_workspace_context(tmp_path):
    boot = gate.build_boot_receipt(
        ROLE,
        control_root=make_control_root(tmp_path),
        workspace_root=make_workspace(tmp_path),
    )
    forged = copy.deepcopy(boot)
    forged["workspace"]["active_open_loop_ids"] = []
    forged["workspace"]["active_open_loops"] = []
    forged["workspace"]["open_loop_count"] = 0
    forged["workspace"]["active_open_loops_digest"] = gate.sha256_canonical([])
    with pytest.raises(gate.AntiAmnesiaError, match="CONTEXT_DIGEST_MISMATCH"):
        gate.validate_boot_receipt(forged)


def test_manual_close_validator_rejects_ready_without_dry_run(tmp_path):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    close = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    close["command"]["dry_run"] = False
    with pytest.raises(gate.AntiAmnesiaError, match="READY_WITHOUT_DRY_RUN"):
        gate.validate_close_receipt(close)


def test_cli_boot_emits_canonical_json_without_legacy_imports(
    tmp_path, monkeypatch, capsys
):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    monkeypatch.setattr(gate, "DEFAULT_CONTROL_ROOT", control)
    monkeypatch.chdir(workspace)

    exit_code = cli.main(["boot", "--role", ROLE])
    stdout = capsys.readouterr().out
    parsed = json.loads(stdout)

    assert exit_code == 0
    assert parsed["schema"] == "ANTI_AMNESIA_BOOT_RECEIPT_V1"
    assert stdout == gate.canonical_json_text(parsed) + "\n"


def test_cli_boot_accepts_explicit_roots_outside_workspace(
    tmp_path, monkeypatch, capsys
):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    exit_code = cli.main(
        [
            "boot",
            "--role",
            ROLE,
            "--control-root",
            str(control),
            "--workspace-root",
            str(workspace),
        ]
    )
    parsed = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert parsed["status"] == "SHADOW_READY"
    assert parsed["workspace"]["files"]


def test_cli_close_accepts_explicit_roots_outside_workspace(
    tmp_path, monkeypatch, capsys
):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    exit_code = cli.main(
        [
            "close",
            "--return",
            str(candidate),
            "--dry-run",
            "--control-root",
            str(control),
            "--workspace-root",
            str(workspace),
        ]
    )
    parsed = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert parsed["status"] == "SHADOW_ACCEPTABLE"
    assert parsed["candidate"]["kind"] == "DIRECTORY"


def test_cli_close_requires_dry_run(tmp_path):
    with pytest.raises(SystemExit) as exc:
        cli.main(["close", "--return", str(tmp_path)])
    assert exc.value.code == 2


def test_cli_close_validates_without_closing(tmp_path, monkeypatch, capsys):
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    monkeypatch.setattr(gate, "DEFAULT_CONTROL_ROOT", control)
    monkeypatch.chdir(workspace)

    exit_code = cli.main(
        ["close", "--return", str(candidate), "--dry-run"]
    )
    parsed = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert parsed["schema"] == "ANTI_AMNESIA_CLOSE_RECEIPT_V1"
    assert parsed["closed"] is False
    assert parsed["writes_performed"] == []


def test_cli_module_does_not_import_legacy_plane_for_shadow_surface():
    project_root = Path(gate.__file__).parents[2]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(project_root)
    code = (
        "import json,sys;"
        "import continuityos.gate.cli;"
        "names=['continuityos.db','continuityos.gate.spec',"
        "'continuityos.gate.engine','continuityos.gate.ledger',"
        "'continuityos.gate.policy'];"
        "print(json.dumps({n:(n in sys.modules) for n in names},sort_keys=True))"
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", code],
        cwd=project_root,
        env=environment,
        text=True,
        capture_output=True,
        check=True,
    )
    assert set(json.loads(result.stdout).values()) == {False}


def test_internal_error_receipt_has_manual_validator():
    receipt = gate.build_internal_error_receipt("boot", RuntimeError("hidden"))
    assert receipt["outcome"] == "WOULD_HOLD"
    assert receipt["writes_performed"] == []
    gate.validate_internal_error_receipt(receipt)


def test_packaged_json_schemas_are_parseable_and_strict():
    schema_root = Path(gate.__file__).parent / "schemas"
    names = {
        "anti_amnesia_boot_receipt_v1.schema.json",
        "anti_amnesia_return_v1.schema.json",
        "anti_amnesia_close_receipt_v1.schema.json",
        "anti_amnesia_cli_internal_error_v1.schema.json",
        "anti_amnesia_return_v1_1.schema.json",
        "anti_amnesia_close_receipt_v1_1.schema.json",
        "anti_amnesia_return_v1_2.schema.json",
        "anti_amnesia_close_receipt_v1_2.schema.json",
        "anti_amnesia_role_permission_policy_v1.schema.json",
        "anti_amnesia_cold_start_spec_v1.schema.json",
        "anti_amnesia_session_capsule_v1.schema.json",
        "anti_amnesia_boot_ack_v1.schema.json",
        "anti_amnesia_cold_start_verdict_v1.schema.json",
        "anti_amnesia_cold_start_challenge_v1.schema.json",
        "anti_amnesia_cold_start_prepare_receipt_v1.schema.json",
        "anti_amnesia_cold_start_internal_error_v1.schema.json",
        "anti_amnesia_session_context_ack_v1.schema.json",
        "anti_amnesia_session_context_binding_v1.schema.json",
        "anti_amnesia_session_context_challenge_v1.schema.json",
        "anti_amnesia_session_context_prepare_receipt_v1.schema.json",
        "anti_amnesia_session_context_verdict_v1.schema.json",
    }
    assert {item.name for item in schema_root.glob("*.schema.json")} == names
    for name in names:
        document = json.loads((schema_root / name).read_text("utf-8"))
        assert document["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert document["additionalProperties"] is False


@pytest.mark.filterwarnings("ignore:jsonschema.RefResolver is deprecated")
def test_receipts_and_return_match_published_json_schemas(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    control = make_control_root(tmp_path)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(
        ROLE, control_root=control, workspace_root=workspace
    )
    candidate = make_return_directory(tmp_path, boot)
    envelope = json.loads(
        (candidate / gate.RETURN_ENVELOPE_NAME).read_text("utf-8")
    )
    close = gate.build_close_receipt(
        candidate, True, control_root=control, workspace_root=workspace
    )
    internal_error = gate.build_internal_error_receipt(
        "close", RuntimeError("hidden")
    )
    schema_root = Path(gate.__file__).parent / "schemas"
    base_uri = schema_root.as_uri() + "/"
    for name, instance in (
        ("anti_amnesia_boot_receipt_v1.schema.json", boot),
        ("anti_amnesia_return_v1.schema.json", envelope),
        ("anti_amnesia_close_receipt_v1.schema.json", close),
        ("anti_amnesia_cli_internal_error_v1.schema.json", internal_error),
    ):
        schema = json.loads((schema_root / name).read_text("utf-8"))
        resolver = jsonschema.RefResolver(base_uri=base_uri, referrer=schema)
        jsonschema.Draft7Validator(schema, resolver=resolver).validate(instance)
