from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from importlib.resources import files as resource_files
from pathlib import Path

import pytest

from continuityos.operational_context import (
    OperationalContextError,
    SCHEMA_PACK,
    SCHEMA_SPEC,
    build_context_pack,
    prepare_context_pack,
    validate_context_spec,
    verify_context_pack,
)
from continuityos.operational_memory import OperationalMemory, PolicyViolation

H1 = "1" * 64
H2 = "2" * 64
T1 = "2026-07-30T20:00:00.000000Z"
T2 = "2026-07-31T20:00:00.000000Z"


def canonical_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def ref(value=H1, locator="evidence://one"):
    return [{"sha256": value, "locator": locator}]


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
        "latest_checkpoint_id": "cp-context",
        "active_open_loop_ids": ["loop-memory"],
        "goal": "Recover bounded operational context from accepted memory.",
        "accepted_decisions": ["R63 remains authority."],
        "rejected_alternatives": ["Do not load the full archive."],
        "allowed_changes": ["Create one context artifact in a disposable output."],
        "forbidden_actions": ["Do not modify repositories.", "Do not apply state."],
        "immutable_decisions": [
            "can_trade=false",
            "capital_permission=DENY",
            "deploy_permission=DENY",
            "self_application=false",
        ],
        "git_baseline": {
            "repository": "bitmaster162/continuityos",
            "branch": "gpt/common-operational-memory-v1-shadow",
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
        "schema": SCHEMA_SPEC,
        "checkpoint_id": "cp-context",
        "subjects": ["role:FABLE-5", "project:continuityos"],
        "claim_predicates": ["status", "memory_gate"],
        "evidence_states": ["VERIFIED", "SOURCE_BACKED", "UNKNOWN"],
        "decision_states": ["HOLD", "PROPOSED"],
        "include_broker_summary": True,
        "max_claims": 10,
        "max_decisions": 10,
        "max_output_bytes": 131072,
        "valid_at": None,
    }
    value.update(overrides)
    return value


def write_registry(path: Path):
    rows = [
        {
            "delivery_id": "d-one",
            "zip_sha256": H1,
            "generation": "R64",
            "slot": "FABLE-5",
            "work_order_id": "WO-ONE",
            "status": "HASH_VERIFIED",
            "secret_payload": "must-never-leak",
        },
        {
            "delivery_id": "d-two",
            "zip_sha256": H2,
            "generation": "R64",
            "slot": "CODEX-01",
            "work_order_id": "WO-TWO",
            "status": "REPORTED",
        },
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def make_memory(tmp_path: Path) -> Path:
    path = tmp_path / "memory.db"
    registry = tmp_path / "registry.jsonl"
    write_registry(registry)
    with OperationalMemory(str(path)) as db:
        db.record_claim(
            subject_id="role:FABLE-5",
            predicate="memory_gate",
            value="PASS_WITH_EXPECTED_WARNING",
            scope="cold-start",
            evidence_state="VERIFIED",
            evidence_refs=ref(),
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="controller",
            valid_from=T1,
            recorded_at=T1,
            claim_id="clm-fable-memory",
        )
        db.record_claim(
            subject_id="project:continuityos",
            predicate="status",
            value="SHADOW_CANDIDATE",
            scope="implementation",
            evidence_state="SOURCE_BACKED",
            evidence_refs=ref(H2, "git://continuityos"),
            actor_type="DETERMINISTIC_CONTROLLER",
            actor_id="controller",
            valid_from=T1,
            recorded_at=T1,
            claim_id="clm-continuity-status",
        )
        db.record_claim(
            subject_id="hidden:subject",
            predicate="secret_note",
            value="not-selected",
            evidence_state="UNKNOWN",
            actor_id="agent",
            valid_from=T1,
            recorded_at=T1,
            claim_id="clm-hidden",
        )
        db.record_decision(
            subject_id="project:continuityos",
            decision_type="live_install",
            state="HOLD",
            value={"install": False},
            rationale="Windows and independent install gates remain open.",
            authority_class="HUMAN",
            authority_id="Robert",
            authority_ref="decision://hold-live-install",
            evidence_refs=ref(),
            decision_id="dec-live-hold",
            recorded_at=T1,
        )
        db.record_decision(
            subject_id="role:FABLE-5",
            decision_type="next_step",
            state="PROPOSED",
            value={"audit": "context-pack"},
            rationale="Audit the bounded context.",
            authority_class="AGENT",
            authority_id="FABLE-5",
            decision_id="dec-fable-proposal",
            recorded_at=T1,
        )
        db.record_decision(
            subject_id="hidden:subject",
            decision_type="hidden",
            state="PROPOSED",
            value={"secret": "not-selected"},
            rationale="Hidden from selected context.",
            authority_class="AGENT",
            authority_id="agent",
            decision_id="dec-hidden",
            recorded_at=T1,
        )
        db.import_broker_registry(registry)
        db.create_checkpoint(
            "operational-context-base",
            checkpoint_id="cp-context",
            evidence_refs=ref(),
            metadata={"purpose": "context", "api_token": "never-export-this-value"},
        )
    return path


def write_inputs(tmp_path: Path, capsule_value=None, spec_value=None):
    capsule_path = tmp_path / "SESSION_CAPSULE.json"
    spec_path = tmp_path / "CONTEXT_SPEC.json"
    capsule_path.write_bytes(canonical_bytes(capsule_value or capsule()))
    spec_path.write_bytes(canonical_bytes(spec_value or spec()))
    return capsule_path, spec_path


def test_prepare_filters_and_binds_context(tmp_path):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path)
    output = tmp_path / "context.json"
    receipt = prepare_context_pack(
        db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, output_path=output
    )
    assert receipt["status"] == "OPERATIONAL_CONTEXT_PACK_READY"
    pack = json.loads(output.read_text("utf-8"))
    assert pack["schema"] == SCHEMA_PACK
    assert pack["authority_generation"] == "R63"
    assert pack["role"] == "FABLE-5"
    assert pack["session_binding"]["session_capsule_sha256"] == sha(capsule_path.read_bytes())
    assert {row["subject_id"] for row in pack["claims"]} == {
        "role:FABLE-5",
        "project:continuityos",
    }
    assert {row["subject_id"] for row in pack["decisions"]} == {
        "role:FABLE-5",
        "project:continuityos",
    }
    assert pack["ceilings"]["accepted_truth_owner"] == "CONTROL_CENTER"
    assert pack["ceilings"]["state_apply"] == "DISABLED"
    assert pack["ceilings"]["can_trade"] is False


def test_broker_summary_is_aggregate_only_and_secret_free(tmp_path):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path)
    output = tmp_path / "context.json"
    prepare_context_pack(
        db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, output_path=output
    )
    raw = output.read_text("utf-8")
    pack = json.loads(raw)
    summary = pack["broker_custody_summary"]
    assert summary["total"] == 2
    assert summary["all_content_unreviewed"] is True
    assert summary["all_state_not_applied"] is True
    assert "must-never-leak" not in raw
    assert "never-export-this-value" not in raw
    assert "metadata_keys" in raw
    assert "api_token" in raw  # the existence of the metadata key is auditable


def test_prepare_is_byte_deterministic_and_database_unchanged(tmp_path):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path)
    before = (db_path.read_bytes(), db_path.stat().st_mtime_ns)
    sidecars_before = sorted(p.name for p in tmp_path.glob("memory.db-*") if p.exists())
    out1 = tmp_path / "one.json"
    out2 = tmp_path / "two.json"
    prepare_context_pack(db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, output_path=out1)
    prepare_context_pack(db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, output_path=out2)
    assert out1.read_bytes() == out2.read_bytes()
    assert before == (db_path.read_bytes(), db_path.stat().st_mtime_ns)
    assert sidecars_before == sorted(p.name for p in tmp_path.glob("memory.db-*") if p.exists())


def test_verify_exact_and_tampered_context(tmp_path):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path)
    output = tmp_path / "context.json"
    prepare_context_pack(db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, output_path=output)
    verdict = verify_context_pack(
        db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, context_path=output
    )
    assert verdict["status"] == "OPERATIONAL_CONTEXT_VERIFY_PASS"
    assert verdict["ok"] is True
    tampered = json.loads(output.read_text("utf-8"))
    tampered["claims"][0]["value"] = "TAMPERED"
    output.write_bytes(canonical_bytes(tampered))
    verdict = verify_context_pack(
        db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, context_path=output
    )
    assert verdict["status"] == "OPERATIONAL_CONTEXT_VERIFY_FAIL"
    assert verdict["ok"] is False


def test_missing_checkpoint_fails_closed(tmp_path):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path, spec_value=spec(checkpoint_id="cp-missing"))
    with pytest.raises(OperationalContextError, match="checkpoint:NOT_FOUND"):
        prepare_context_pack(
            db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path,
            output_path=tmp_path / "context.json",
        )


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"max_claims": 1}, "CLAIM_BUDGET_EXCEEDED"),
        ({"max_decisions": 1}, "DECISION_BUDGET_EXCEEDED"),
        ({"max_output_bytes": 4096}, "OUTPUT_BUDGET_EXCEEDED"),
    ],
)
def test_budgets_fail_closed(tmp_path, overrides, match):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path, spec_value=spec(**overrides))
    with pytest.raises(OperationalContextError, match=match):
        prepare_context_pack(
            db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path,
            output_path=tmp_path / "context.json",
        )


def test_valid_at_and_predicate_filters(tmp_path):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(
        tmp_path,
        spec_value=spec(
            subjects=["project:continuityos"],
            claim_predicates=["status"],
            decision_states=["HOLD"],
            valid_at="2026-07-31T20:00:00Z",
        ),
    )
    output = tmp_path / "context.json"
    prepare_context_pack(db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, output_path=output)
    pack = json.loads(output.read_text("utf-8"))
    assert [row["predicate"] for row in pack["claims"]] == ["status"]
    assert [row["state"] for row in pack["decisions"]] == ["HOLD"]
    assert pack["memory_binding"]["context_valid_at"] == T2


def test_broker_summary_can_be_disabled(tmp_path):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path, spec_value=spec(include_broker_summary=False))
    output = tmp_path / "context.json"
    prepare_context_pack(db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, output_path=output)
    assert json.loads(output.read_text("utf-8"))["broker_custody_summary"] is None


@pytest.mark.parametrize(
    "capsule_value",
    [
        capsule(can_trade=True),
        capsule(may_dispatch_codex=True),
        capsule(effect_ceiling="IRREVERSIBLE"),
        capsule(immutable_decisions=["can_trade=false", "capital_permission=DENY"]),
        capsule(git_baseline={
            "repository": "bitmaster162/continuityos",
            "branch": "b",
            "head": "4" * 40,
            "tree": "5" * 40,
            "porcelain": "?? dirty",
        }),
    ],
)
def test_capsule_permission_or_baseline_escalation_rejected(tmp_path, capsule_value):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path, capsule_value=capsule_value)
    with pytest.raises(OperationalContextError):
        prepare_context_pack(
            db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path,
            output_path=tmp_path / "context.json",
        )


def test_capsule_extra_field_rejected(tmp_path):
    db_path = make_memory(tmp_path)
    value = capsule()
    value["hidden_hint"] = "not allowed"
    capsule_path, spec_path = write_inputs(tmp_path, capsule_value=value)
    with pytest.raises(OperationalContextError, match="session_capsule:KEYS"):
        prepare_context_pack(
            db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path,
            output_path=tmp_path / "context.json",
        )


def test_spec_duplicate_subjects_and_invalid_states_rejected():
    with pytest.raises(OperationalContextError, match="DUPLICATE_ITEMS"):
        validate_context_spec(spec(subjects=["a", "a"]))
    with pytest.raises(OperationalContextError, match="evidence_states:INVALID"):
        validate_context_spec(spec(evidence_states=["MAGIC"]))


def test_build_requires_read_only_memory_handle(tmp_path):
    db_path = make_memory(tmp_path)
    with OperationalMemory(str(db_path)) as memory:
        with pytest.raises(PolicyViolation, match="read-only"):
            build_context_pack(
                memory,
                capsule=capsule(),
                capsule_sha256=H1,
                spec=spec(),
                spec_sha256=H2,
            )


def test_existing_output_is_never_overwritten(tmp_path):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path)
    output = tmp_path / "context.json"
    output.write_text("sentinel", encoding="utf-8")
    with pytest.raises(OperationalContextError, match="TARGET_ALREADY_EXISTS"):
        prepare_context_pack(db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, output_path=output)
    assert output.read_text("utf-8") == "sentinel"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink unsupported")
def test_symlink_capsule_is_refused(tmp_path):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path)
    link = tmp_path / "capsule-link.json"
    try:
        link.symlink_to(capsule_path)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(OperationalContextError, match="SYMLINK_REFUSED"):
        prepare_context_pack(db_path=str(db_path), capsule_path=link, spec_path=spec_path, output_path=tmp_path / "context.json")


def test_context_hash_is_hash_of_body_without_hash_field(tmp_path):
    db_path = make_memory(tmp_path)
    capsule_path, spec_path = write_inputs(tmp_path)
    output = tmp_path / "context.json"
    prepare_context_pack(db_path=str(db_path), capsule_path=capsule_path, spec_path=spec_path, output_path=output)
    pack = json.loads(output.read_text("utf-8"))
    context_hash = pack.pop("context_sha256")
    assert context_hash == hashlib.sha256(canonical_bytes(pack)).hexdigest()


def test_immutable_open_rejects_nonempty_wal(tmp_path):
    path = tmp_path / "active.db"
    writer = OperationalMemory(str(path))
    try:
        writer.append_event(
            stream="ops", event_type="ACTIVE", subject_id="x", actor_type="AGENT",
            actor_id="a", payload={}, occurred_at=T1,
        )
        wal = Path(str(path) + "-wal")
        assert wal.exists() and wal.stat().st_size > 0
        with pytest.raises(PolicyViolation, match="quiescent"):
            OperationalMemory(str(path), read_only=True, immutable=True)
    finally:
        writer.close()


def test_packaged_schemas_are_strict_and_cover_examples():
    jsonschema = pytest.importorskip("jsonschema")
    schema_root = resource_files("continuityos.operational_context_schemas")
    spec_schema = json.loads(
        (schema_root / "operational_context_spec_v1.schema.json").read_text(encoding="utf-8")
    )
    pack_schema = json.loads(
        (schema_root / "operational_context_pack_v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft7Validator(spec_schema).validate(spec())
    assert spec_schema["additionalProperties"] is False
    assert pack_schema["additionalProperties"] is False
