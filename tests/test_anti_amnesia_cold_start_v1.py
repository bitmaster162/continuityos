from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from continuityos.gate import anti_amnesia as gate
from continuityos.gate import cold_start
from continuityos.gate import cli

ROLE = "CODEX-01"
CASE_ID = "WO-COLD-001"

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
    role_record = {"state": "READY", "lane": "ContinuityOS"}
    if case_id is not None:
        role_record["case_id"] = case_id
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
        [{"id": "loop-1", "title": "Cold start", "status": "open", "next_action": "Verify"}],
    )
    (root / "01_RUNTIME" / "checkpoints.jsonl").write_bytes(
        canonical_bytes({"checkpoint_id": "cp-1"}) + b"\n"
    )
    return root


def make_spec(path: Path, *, case_id=CASE_ID, role=ROLE, overrides=None):
    spec = {
        "schema": cold_start.SCHEMA_SPEC,
        "authority_generation": "R63",
        "work_order_id": case_id or "ROLE-ONLY-COLD-START",
        "role": role,
        "case_id": case_id,
        "goal": "Prove fresh-session continuity from one capsule.",
        "accepted_decisions": ["R63 remains authority."],
        "rejected_alternatives": ["No archive rescan."],
        "allowed_changes": ["Create BOOT_ACK.json in the assigned output directory only."],
        "forbidden_actions": ["Do not modify repositories.", "Do not dispatch Codex."],
        "immutable_decisions": ["can_trade=false", "capital_permission=DENY"],
        "git_baseline": {
            "repository": "bitmaster162/continuityos",
            "branch": "gpt/anti-amnesia-cold-start-v1",
            "head": "1" * 40,
            "tree": "2" * 40,
            "porcelain": "",
        },
        "next_action": "Read SESSION_CAPSULE.json and emit one exact BOOT_ACK.json.",
        "terminal_condition": "BOOT_ACK.json emitted; stop without other work.",
        "effect_ceiling": "READ_ONLY",
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }
    spec.update(overrides or {})
    path.write_bytes(canonical_bytes(spec))
    return spec


def prepare(tmp_path: Path, *, case_id=CASE_ID):
    control = make_control_root(tmp_path, case_id=case_id)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(ROLE, case_id, control_root=control, workspace_root=workspace)
    boot_path = tmp_path / "BOOT_RECEIPT.json"
    boot_path.write_bytes(canonical_bytes(boot))
    spec_path = tmp_path / "COLD_START_SPEC.json"
    make_spec(spec_path, case_id=case_id)
    out = tmp_path / "challenge"
    receipt = cold_start.prepare_cold_start_challenge(boot_path, spec_path, out)
    return out, receipt


def test_prepare_and_exact_verify_pass(tmp_path):
    out, receipt = prepare(tmp_path)
    assert receipt["status"] == "COLD_START_CHALLENGE_READY"
    challenge = json.loads((out / "COLD_START_CHALLENGE.json").read_text("utf-8"))
    expected = (out / "controller" / "EXPECTED_BOOT_ACK.json").read_bytes()
    ack = tmp_path / "BOOT_ACK.json"
    ack.write_bytes(expected)
    verdict = cold_start.verify_cold_start_ack(
        out / "COLD_START_CHALLENGE.json",
        ack,
        expected_challenge_sha256=receipt["challenge_sha256"],
    )
    assert verdict["outcome"] == "PASS"
    assert verdict["status"] == "COLD_START_PASS"
    assert verdict["release_blocked"] is False
    assert verdict["mismatches"] == []
    assert challenge["challenge_id"] == receipt["challenge_id"]


def test_role_only_challenge_is_supported(tmp_path):
    out, _receipt = prepare(tmp_path, case_id=None)
    capsule = json.loads((out / "candidate" / "SESSION_CAPSULE.json").read_text("utf-8"))
    assert capsule["active_case"] is None
    assert capsule["case_binding"] == "NOT_REQUESTED"


def test_prepare_rejects_case_mismatch(tmp_path):
    control = make_control_root(tmp_path, case_id=CASE_ID)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(ROLE, CASE_ID, control_root=control, workspace_root=workspace)
    boot_path = tmp_path / "BOOT.json"
    boot_path.write_bytes(canonical_bytes(boot))
    spec_path = tmp_path / "SPEC.json"
    make_spec(spec_path, case_id="OTHER-CASE")
    with pytest.raises(cold_start.ColdStartError, match="CASE_MISMATCH"):
        cold_start.prepare_cold_start_challenge(boot_path, spec_path, tmp_path / "out")


def test_prepare_rejects_hold_boot(tmp_path):
    control = make_control_root(tmp_path, case_id=CASE_ID)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(ROLE, "WRONG", control_root=control, workspace_root=workspace)
    assert boot["outcome"] == "WOULD_HOLD"
    boot_path = tmp_path / "BOOT.json"
    boot_path.write_bytes(canonical_bytes(boot))
    spec_path = tmp_path / "SPEC.json"
    make_spec(spec_path, case_id="WRONG")
    with pytest.raises(cold_start.ColdStartError, match="NOT_ADMISSIBLE"):
        cold_start.prepare_cold_start_challenge(boot_path, spec_path, tmp_path / "out")


def test_prepare_requires_clean_git_baseline(tmp_path):
    spec_path = tmp_path / "SPEC.json"
    make_spec(spec_path, overrides={"git_baseline": {"repository": "x", "branch": "b", "head": "1" * 40, "tree": "2" * 40, "porcelain": "?? file"}})
    raw = json.loads(spec_path.read_text("utf-8"))
    with pytest.raises(cold_start.ColdStartError, match="BASELINE_NOT_CLEAN"):
        cold_start.validate_cold_start_spec(raw)


def test_prepare_refuses_nonempty_output(tmp_path):
    control = make_control_root(tmp_path, case_id=CASE_ID)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(ROLE, CASE_ID, control_root=control, workspace_root=workspace)
    boot_path = tmp_path / "BOOT.json"
    boot_path.write_bytes(canonical_bytes(boot))
    spec_path = tmp_path / "SPEC.json"
    make_spec(spec_path)
    out = tmp_path / "out"
    out.mkdir()
    (out / "existing.txt").write_text("x", encoding="utf-8")
    with pytest.raises(cold_start.ColdStartError, match="TARGET_ALREADY_EXISTS"):
        cold_start.prepare_cold_start_challenge(boot_path, spec_path, out)


def test_verify_reports_field_mismatch(tmp_path):
    out, _receipt = prepare(tmp_path)
    expected = json.loads((out / "controller" / "EXPECTED_BOOT_ACK.json").read_text("utf-8"))
    expected["may_dispatch_codex"] = False
    expected["next_action"] = "Invent a different next action."
    ack = tmp_path / "BOOT_ACK.json"
    ack.write_bytes(canonical_bytes(expected))
    challenge_sha = digest((out / "COLD_START_CHALLENGE.json").read_bytes())
    verdict = cold_start.verify_cold_start_ack(
        out / "COLD_START_CHALLENGE.json", ack, expected_challenge_sha256=challenge_sha
    )
    assert verdict["outcome"] == "FAIL"
    assert verdict["release_blocked"] is True
    assert [row["path"] for row in verdict["mismatches"]] == ["/next_action"]


def test_verify_rejects_extra_ack_key(tmp_path):
    out, _receipt = prepare(tmp_path)
    expected = json.loads((out / "controller" / "EXPECTED_BOOT_ACK.json").read_text("utf-8"))
    expected["commentary"] = "not allowed"
    ack = tmp_path / "BOOT_ACK.json"
    ack.write_bytes(canonical_bytes(expected))
    challenge_sha = digest((out / "COLD_START_CHALLENGE.json").read_bytes())
    verdict = cold_start.verify_cold_start_ack(
        out / "COLD_START_CHALLENGE.json", ack, expected_challenge_sha256=challenge_sha
    )
    assert verdict["outcome"] == "FAIL"
    assert verdict["checks"][0]["check_id"] == "ack.schema"


def test_verify_rejects_tampered_hidden_expected_ack(tmp_path):
    out, _receipt = prepare(tmp_path)
    expected_path = out / "controller" / "EXPECTED_BOOT_ACK.json"
    expected_path.write_bytes(expected_path.read_bytes() + b"\n")
    ack = tmp_path / "BOOT_ACK.json"
    ack.write_bytes(b"{}")
    challenge_sha = digest((out / "COLD_START_CHALLENGE.json").read_bytes())
    with pytest.raises(cold_start.ColdStartError, match="EXPECTED_ACK_SHA_MISMATCH"):
        cold_start.verify_cold_start_ack(
            out / "COLD_START_CHALLENGE.json", ack, expected_challenge_sha256=challenge_sha
        )


def test_verify_requires_controller_pinned_challenge_hash(tmp_path):
    out, _receipt = prepare(tmp_path)
    ack = tmp_path / "BOOT_ACK.json"
    ack.write_bytes((out / "controller" / "EXPECTED_BOOT_ACK.json").read_bytes())
    with pytest.raises(cold_start.ColdStartError, match="SHA256_MISMATCH"):
        cold_start.verify_cold_start_ack(
            out / "COLD_START_CHALLENGE.json",
            ack,
            expected_challenge_sha256="0" * 64,
        )


def test_cli_prepare_and_verify(tmp_path, capsys):
    control = make_control_root(tmp_path, case_id=CASE_ID)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(ROLE, CASE_ID, control_root=control, workspace_root=workspace)
    boot_path = tmp_path / "BOOT.json"
    boot_path.write_bytes(canonical_bytes(boot))
    spec_path = tmp_path / "SPEC.json"
    make_spec(spec_path)
    out = tmp_path / "out"
    code = cli.main([
        "cold-start", "prepare", "--boot-receipt", str(boot_path), "--spec", str(spec_path), "--output", str(out)
    ])
    assert code == 0
    prepare_receipt = json.loads(capsys.readouterr().out)
    assert prepare_receipt["status"] == "COLD_START_CHALLENGE_READY"
    ack = tmp_path / "ACK.json"
    ack.write_bytes((out / "controller" / "EXPECTED_BOOT_ACK.json").read_bytes())
    code = cli.main([
        "cold-start", "verify", "--challenge", str(out / "COLD_START_CHALLENGE.json"),
        "--challenge-sha256", digest((out / "COLD_START_CHALLENGE.json").read_bytes()),
        "--ack", str(ack)
    ])
    assert code == 0
    verdict = json.loads(capsys.readouterr().out)
    assert verdict["status"] == "COLD_START_PASS"


def test_prepare_does_not_modify_inputs(tmp_path):
    control = make_control_root(tmp_path, case_id=CASE_ID)
    workspace = make_workspace(tmp_path)
    boot = gate.build_boot_receipt(ROLE, CASE_ID, control_root=control, workspace_root=workspace)
    boot_path = tmp_path / "BOOT.json"
    boot_path.write_bytes(canonical_bytes(boot))
    spec_path = tmp_path / "SPEC.json"
    make_spec(spec_path)
    before = {p: digest(p.read_bytes()) for p in [boot_path, spec_path]}
    cold_start.prepare_cold_start_challenge(boot_path, spec_path, tmp_path / "out")
    after = {p: digest(p.read_bytes()) for p in [boot_path, spec_path]}
    assert before == after


def test_write_new_requests_binary_mode_and_preserves_multiline_bytes(tmp_path, monkeypatch):
    """Raw challenge artifacts must not receive Windows newline translation.

    The spy must preserve the host's real ``O_BINARY`` bit on Windows.  The
    previous test always stripped ``0x8000`` before delegating to ``os.open``;
    that value is the native Windows ``O_BINARY`` flag, so the test itself
    forced text mode and produced CRLF bytes even though production code had
    requested binary mode correctly.
    """
    destination = tmp_path / "multiline.json"
    payload = b'{\n  "schema": "TEST"\n}\n'
    observed_flags = []
    real_open = cold_start.os.open
    native_o_binary = getattr(cold_start.os, "O_BINARY", 0)
    requested_o_binary = native_o_binary or 0x40000000

    monkeypatch.setattr(
        cold_start.os, "O_BINARY", requested_o_binary, raising=False
    )

    def capturing_open(path, flags, mode=0o777):
        observed_flags.append(flags)
        # On POSIX the synthetic bit is assertion-only and must be removed
        # before the real syscall.  On Windows preserve the native O_BINARY
        # flag so the delegated open remains binary.
        host_flags = flags if native_o_binary else flags & ~requested_o_binary
        return real_open(path, host_flags, mode)

    monkeypatch.setattr(cold_start.os, "open", capturing_open)
    cold_start._write_new(destination, payload)

    assert observed_flags
    assert observed_flags[0] & requested_o_binary
    assert destination.read_bytes() == payload
