from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import continuityos.current_cold_start as current
from continuityos.gate.state_resolution import CANDIDATE_SCHEMA


def write_json(path: Path, value) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def candidate(kind, status, when, artifact_id, **extra):
    row = {
        "schema": CANDIDATE_SCHEMA,
        "subject": "P0_SECURITY",
        "artifact_id": artifact_id,
        "kind": kind,
        "status": status,
        "observed_at_utc": when,
    }
    row.update(extra)
    return row


def build_fixture(tmp_path: Path, *, fresh_contradiction=False, inactive_pointer=False, role="GPT_RUNTIME_CURRENT", effect="READ_ONLY"):
    effect_ceiling = {
        "NO_FURTHER_AGENT_WORK": True,
        "auto_accept": False,
        "auto_dispatch": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy": "DENY",
        "external_messages": "DENY_WITHOUT_EXACT_SEPARATE_HUMAN_AUTHORIZATION",
        "push": "DENY_WITHOUT_EXPLICIT_BOUNDED_AUTHORITY",
        "self_application": False,
    }

    current_state = {
        "schema": "CONTROL_CURRENT_STATE_R64",
        "generation": "R64",
        "canonicality_activation": "CANDIDATE_NOT_ACTIVE_PENDING_ROBERT",
        "global_effect_ceiling": dict(effect_ceiling),
    }
    role_index = {
        "schema": "CONTROL_ROLE_INDEX_R64",
        "generation": "R64",
        "current_state": {"path": "CURRENT_STATE.json"},
        "role_views": {
            "GPT_RUNTIME_CURRENT": {
                "path": "ROLE_VIEWS.json",
                "json_pointer": "/roles/GPT_RUNTIME_CURRENT",
            },
            "WORK": {"path": "ROLE_VIEWS.json", "json_pointer": "/roles/WORK"},
        },
    }
    role_views = {
        "schema": "CONTROL_ROLE_VIEWS_R64",
        "generation": "R64",
        "global_effect_ceiling": dict(effect_ceiling),
        "roles": {
            "GPT_RUNTIME_CURRENT": {
                "role": "CURRENT_BUILD_CONTROLLER",
                "state": "ACTIVE_CONTROL_PLANE",
                "must": ["load CURRENT_POINTER then CURRENT_STATE", "never self-apply authority-changing state"],
            },
            "WORK": {"role": "CONTROL_PLANE", "must": ["advance one bounded real-world gate"]},
        },
    }

    current_state_path = tmp_path / "CURRENT_STATE.json"
    role_index_path = tmp_path / "ROLE_INDEX.json"
    role_views_path = tmp_path / "ROLE_VIEWS.json"
    current_state_sha = write_json(current_state_path, current_state)
    role_index_sha = write_json(role_index_path, role_index)
    role_views_sha = write_json(role_views_path, role_views)

    manifest_sha = "4" * 64
    pointer = {
        "schema": "CONTROL_CURRENT_POINTER_R64",
        "generation": "R64",
        "published_at_utc": "2026-08-07T20:34:00Z",
        "canonical_activation": {
            "status": "INACTIVE" if inactive_pointer else "ACTIVE",
            "generation": "R64",
            "decision": "ACCEPT_R64_POINTER_PROMOTION",
            "accepted_manifest_sha256": manifest_sha,
            "human_sovereign": "ROBERT",
            "stable_root_provider_readback": {"all_exact": True},
        },
        "manifest": {"sha256": manifest_sha},
        "effect_ceiling": dict(effect_ceiling),
        "current_state": {"sha256": current_state_sha},
        "role_index": {"sha256": role_index_sha},
        "role_views": {"sha256": role_views_sha},
    }
    pointer_path = tmp_path / "CURRENT_POINTER.json"
    pointer_sha = write_json(pointer_path, pointer)

    rows = [
        candidate("TEMPLATE", "OPEN", "2026-07-29T21:22:45Z", "STALE_TEMPLATE"),
        candidate(
            "HUMAN_DECISION",
            "PASS_WITH_CONDITIONS",
            "2026-07-31T03:00:00Z",
            "OPERATIONAL_CLOSURE",
            evidence_debt=True,
        ),
    ]
    if fresh_contradiction:
        rows.append(
            candidate(
                "PROVIDER_READBACK",
                "OPEN",
                "2026-08-09T04:00:00Z",
                "FRESH_READBACK",
                current_observation=True,
            )
        )
    bundle_path = tmp_path / "state_bundle.json"
    write_json(bundle_path, {"schema": current.BUNDLE_SCHEMA, "candidates": rows})

    spec = {
        "schema": current.SCHEMA_SPEC,
        "authority_generation": "R64",
        "authority_pointer_sha256": pointer_sha,
        "required_state_subject": "P0_SECURITY",
        "session_id": "continuityos-r23-test",
        "work_order_id": None,
        "role": role,
        "case_id": None,
        "goal": "Load current ContinuityOS authority without archive rescan.",
        "accepted_decisions": ["R64 pointer ACTIVE", "P0 operational closure PASS WITH CONDITIONS"],
        "rejected_alternatives": ["Treat stale OPEN template as current truth"],
        "immutable_decisions": ["can_trade=false", "capital_permission=DENY", "deploy_permission=DENY"],
        "git_baseline": {
            "repository": "bitmaster162/continuityos",
            "branch": "gpt/merge-execution-receipt-gate-v1-r14",
            "head": "b" * 40,
            "tree": "c" * 40,
        },
        "next_action": "Read current capsule and return exact BOOT_ACK.",
        "terminal_condition": "Exact BOOT_ACK verified.",
        "effect_ceiling": effect,
        "may_dispatch_codex": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }
    spec_path = tmp_path / "CURRENT_COLD_START_SPEC.json"
    write_json(spec_path, spec)

    return {
        "pointer": pointer_path,
        "pointer_sha": pointer_sha,
        "current_state": current_state_path,
        "role_index": role_index_path,
        "role_views": role_views_path,
        "bundle": bundle_path,
        "spec": spec_path,
        "out": tmp_path / "out",
    }


def prepare(fx):
    return current.prepare_current_cold_start(
        authority_pointer_path=fx["pointer"],
        expected_authority_pointer_sha256=fx["pointer_sha"],
        current_state_path=fx["current_state"],
        role_index_path=fx["role_index"],
        role_views_path=fx["role_views"],
        state_bundle_path=fx["bundle"],
        spec_path=fx["spec"],
        output_dir=fx["out"],
    )


def test_current_prepare_binds_active_r64_and_supersedes_compiled_candidate_marker(tmp_path):
    fx = build_fixture(tmp_path)
    result = prepare(fx)

    assert result["terminal"] == "CURRENT_COLD_START_PASS"
    assert result["authority_generation"] == "R64"
    assert result["authority_pointer_sha256"] == fx["pointer_sha"]
    assert result["effects"]["can_trade"] is False
    assert result["effects"]["capital_permission"] == "DENY"

    challenge = json.loads((fx["out"] / "CURRENT_COLD_START_CHALLENGE.json").read_text())
    capsule = json.loads((fx["out"] / "candidate" / "SESSION_CAPSULE.json").read_text())
    assert challenge["authority_generation"] == "R64"
    assert capsule["authority_generation"] == "R64"
    assert capsule["compiled_current_state_marker"] == "CANDIDATE_NOT_ACTIVE_PENDING_ROBERT"
    assert "ACTIVE canonical_activation" in capsule["compiled_marker_interpretation"]
    assert capsule["state_selected_artifact_id"] == "OPERATIONAL_CLOSURE"
    assert capsule["state_status"] == "PASS_WITH_CONDITIONS"
    assert capsule["effect_ceiling"] == "READ_ONLY"
    assert capsule["no_repo_writes"] is True


def test_exact_expected_ack_verifies_pass(tmp_path):
    fx = build_fixture(tmp_path)
    result = prepare(fx)
    ack = tmp_path / "BOOT_ACK.json"
    ack.write_bytes((fx["out"] / "controller" / "EXPECTED_BOOT_ACK.json").read_bytes())

    verdict = current.verify_current_cold_start_ack(
        fx["out"] / "CURRENT_COLD_START_CHALLENGE.json",
        ack,
        expected_challenge_sha256=result["challenge_sha256"],
    )
    assert verdict["outcome"] == "PASS"
    assert verdict["authority_generation"] == "R64"
    assert verdict["release_blocked"] is False


def test_ack_mismatch_fails_without_effects(tmp_path):
    fx = build_fixture(tmp_path)
    result = prepare(fx)
    ack = json.loads((fx["out"] / "controller" / "EXPECTED_BOOT_ACK.json").read_text())
    ack["next_action"] = "wrong"
    ack_path = tmp_path / "BOOT_ACK.json"
    write_json(ack_path, ack)

    verdict = current.verify_current_cold_start_ack(
        fx["out"] / "CURRENT_COLD_START_CHALLENGE.json",
        ack_path,
        expected_challenge_sha256=result["challenge_sha256"],
    )
    assert verdict["outcome"] == "FAIL"
    assert verdict["release_blocked"] is True
    assert verdict["effects"]["can_trade"] is False


def test_pointer_sha_mismatch_fails_before_output(tmp_path):
    fx = build_fixture(tmp_path)
    fx["pointer_sha"] = "0" * 64
    with pytest.raises(current.CurrentColdStartError, match="SHA256_MISMATCH"):
        prepare(fx)
    assert not fx["out"].exists()


def test_root_hash_mismatch_fails_before_output(tmp_path):
    fx = build_fixture(tmp_path)
    fx["role_views"].write_text("{}", encoding="utf-8")
    with pytest.raises(current.CurrentColdStartError, match="POINTER_SHA_MISMATCH"):
        prepare(fx)
    assert not fx["out"].exists()


def test_inactive_pointer_fails_closed(tmp_path):
    fx = build_fixture(tmp_path, inactive_pointer=True)
    with pytest.raises(current.CurrentColdStartError, match="NOT_ACTIVE"):
        prepare(fx)
    assert not fx["out"].exists()


def test_fresh_provider_contradiction_holds_without_writes(tmp_path):
    fx = build_fixture(tmp_path, fresh_contradiction=True)
    result = prepare(fx)
    assert result["terminal"] == "CURRENT_COLD_START_HOLD"
    assert result["reason"] == "STATE_RESOLUTION_NOT_PASS"
    assert result["state_resolution"]["reason"] == "FRESH_CURRENT_CONTRADICTION"
    assert result["writes_performed"] == []
    assert not fx["out"].exists()


def test_unknown_role_fails_before_output(tmp_path):
    fx = build_fixture(tmp_path, role="UNKNOWN")
    with pytest.raises(current.CurrentColdStartError, match="NOT_IN_R64_ROOTS"):
        prepare(fx)
    assert not fx["out"].exists()


def test_non_read_only_spec_is_rejected_even_for_current_protocol(tmp_path):
    fx = build_fixture(tmp_path, effect="REVERSIBLE_LOCAL_IMPLEMENTATION")
    with pytest.raises(current.CurrentColdStartError, match="MUST_BE_READ_ONLY"):
        prepare(fx)
    assert not fx["out"].exists()


def test_challenge_schema_peek_distinguishes_current(tmp_path):
    fx = build_fixture(tmp_path)
    prepare(fx)
    assert (
        current.peek_challenge_schema(fx["out"] / "CURRENT_COLD_START_CHALLENGE.json")
        == current.SCHEMA_CHALLENGE
    )
