"""Product proof of synthetic Person continuity across real Python processes.

The Person contracts, admission readback, SQLite reads, and R21H prompt path are
real. Model clients only capture calls; synthetic host fixtures are not live OS
authority, cross-model inference, or a Portable Twin Vault restore.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import sys

import pytest

from continuityos import current_entrypoints, db, demo
from continuityos import person_twin_demo as person_demo
from continuityos.person_twin_admission_contracts import (
    build_consent_revocation_entry,
    build_consent_revocation_ledger,
)


def _fixture(tmp_path):
    root = tmp_path / ("continuityos-person-demo-" + secrets.token_hex(16))
    root.mkdir()
    written = person_demo._write_fixture(root, secrets.token_hex(16))
    return root, written


def _assert_hold(value, code):
    assert code == 2
    assert value["terminal"].endswith("_HOLD")


def _controlled_root(tmp_path, monkeypatch):
    root = tmp_path / ("continuityos-person-demo-" + secrets.token_hex(16))

    def create_owned_root(*args, **kwargs):
        root.mkdir()
        return str(root)

    monkeypatch.setattr(person_demo.tempfile, "mkdtemp", create_owned_root)
    return root


@pytest.fixture(scope="module")
def completed_person_demo(tmp_path_factory):
    """One real PREPARE/A/B run; observe bytes without replacing either worker."""
    sandbox = tmp_path_factory.mktemp("person-continuity-proof")
    user_db = sandbox / "user-memory.db"
    user_db.write_bytes(b"synthetic-user-memory-sentinel")
    user_before = user_db.read_bytes()
    shadow = sandbox / "shadow-import-origin"
    (shadow / "continuityos").mkdir(parents=True)
    (shadow / "continuityos" / "__init__.py").write_text(
        "raise RuntimeError('SYNTHETIC_WRONG_IMPORT_ORIGIN')\n", encoding="utf-8",
    )
    observations = []
    commands = []
    original_command = person_demo._child_command
    original_worker = person_demo._run_worker

    def observed_command(*arguments):
        command = original_command(*arguments)
        commands.append((arguments, list(command)))
        if arguments[0] == "_worker":
            # These real reader children must succeed with every write entry
            # disabled: neither SQL admission nor R3 receipt regeneration is a fallback.
            prelude = ("from continuityos.person_twin_admission_store import PersonTwinAdmissionStore as S\n"
                       "from continuityos.person_twin_admission_coordinator import PersonTwinAdmissionCoordinator as C\n"
                       "def forbidden(*a, **kw): raise AssertionError('READER_ADMISSION_WRITE_FORBIDDEN')\n"
                       "S.initialize = forbidden\nS.admit = forbidden\nC.promote_current = forbidden\n")
            command[4] = command[4].replace("runpy.run_module(", "exec(" + repr(prelude) + "); runpy.run_module(", 1)
        return command

    def observe_worker(root, expected_sha256, role, timeout, run_id):
        assert {item.name for item in root.iterdir()} == {"memory.db"}
        before = {"memory.db": (root / "memory.db").read_bytes()}
        fixture = person_demo._read_fixture(root, expected_sha256, run_id)
        con = sqlite3.connect((root / "memory.db").as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            rows = con.execute("SELECT id, namespace, text, meta FROM items ORDER BY id").fetchall()
        finally:
            con.close()
        result = original_worker(root, expected_sha256, role, timeout, run_id)
        after = {name: (root / name).read_bytes() for name in before}
        observations.append({
            "role": role, "before": before, "after": after,
            "fixture": fixture, "rows": rows, "result": result,
        })
        return result

    with pytest.MonkeyPatch.context() as patch:
        root = _controlled_root(sandbox, patch)
        patch.setenv("CONTINUITYOS_DB", str(user_db))
        # Workers must use the already imported parent's package, even when a
        # same-named package exists at both ambient import-origin entry points.
        patch.chdir(shadow)
        patch.setenv("PYTHONPATH", str(shadow))
        patch.setattr(person_demo, "_run_worker", observe_worker)
        patch.setattr(person_demo, "_child_command", observed_command)
        value, code = person_demo.run_person_continuity(timeout=20.0)

    assert code == 0, (value, [o['result'] for o in observations])
    assert len(commands) == 3
    for args, command in commands[1:]:
        assert len(args) == 9 and args[0] == "_worker"
        assert args[1] == "--root" and args[3] == "--db-sha256"
        assert args[5] == "--role" and args[7] == "--run-id"
        assert args[8] == value["run_id"]
        assert not any("fixture.json" in item or '"admission_receipt"' in item for item in command[7:])
    assert not root.exists()
    assert user_db.read_bytes() == user_before
    return value, observations


def test_person_continuity_recovers_actual_current_evidence_across_processes(completed_person_demo):
    value, observations = completed_person_demo
    assert value["terminal"] == "COS_DEMO_PERSON_CONTINUITY_PASS"
    assert value["orchestrator_process_id"] == os.getpid()
    assert [entry["role"] for entry in observations] == ["A", "B"]
    assert len(value["processes"]) == value["effects"]["child_launches"] == 3
    process_ids = [process["process_id"] for process in value["processes"]]
    assert len(set(process_ids)) == 3
    assert os.getpid() not in process_ids
    assert value["prepare"]["process_id"] == process_ids[0]
    assert all(process["returncode"] == 0 and process["direct_child_reaped"] is True
               for process in value["processes"])
    source_sha = hashlib.sha256(Path(person_demo.__file__).read_bytes()).hexdigest()
    assert value["source_sha256"] == value["prepare"]["source_sha256"] == source_sha

    first, second = observations
    assert first["before"] == first["after"] == second["before"] == second["after"]
    fixture = first["fixture"]
    memory_id = fixture["memory"]["id"]
    current_row = next(row for row in first["rows"] if row[0] == memory_id)
    assert current_row[1] == fixture["memory"]["namespace"]
    assert current_row[2] == fixture["context"]["source_record"]["payload"]["text"]
    old_rows = [row for row in first["rows"]
                if json.loads(row[3]).get("superseded_by") == memory_id]
    assert old_rows, "The persisted history must include a superseded decision"
    expected = [{"ref": f"mem:{memory_id}", "namespace": current_row[1], "text": current_row[2]}]
    a, b = (value["sessions"][role] for role in ("A", "B"))
    assert a["captured_evidence"] == b["captured_evidence"] == expected
    assert all(row[2] not in item["text"] for row in old_rows for item in b["captured_evidence"])
    assert a["process_id"] == process_ids[1] and b["process_id"] == process_ids[2]
    assert a["transport"] == "warm_chat" and b["transport"] == "cold_streaming"
    assert a["model_calls"] == b["model_calls"] == 1
    assert a["model_events"].count("chat") == 1 and "stream" not in a["model_events"]
    assert b["model_events"].count("stream") == 1 and "chat" not in b["model_events"]
    assert a["model_profile"] != b["model_profile"]
    assert a["session_sha256"] != b["session_sha256"]
    assert a["request_sha256"] != b["request_sha256"]
    assert a["packet_sha256"] != b["packet_sha256"]
    for key in ("intent_sha256", "r4_receipt_hash", "receipt_hash"):
        assert a["person_evidence"][key] != b["person_evidence"][key]
    assert a["person_evidence"]["evidence_sha256"] == b["person_evidence"]["evidence_sha256"]
    for worker in (a, b):
        assert worker["source_sha256"] == source_sha
        assert worker["context_reads"] >= 2
        assert worker["person_evidence"]["prompt_boundary_revalidated"] is True
        assert worker["checks"]["query_only"] is True
        assert worker["unsupported_execute"]["decision"] == "DENY"
        assert worker["unsupported_execute"]["execution_authorized"] is False
        assert worker["socket_audit"] == {
            "installed": True, "events": 0, "policy": "DENY_SOCKET_EVENTS",
        }

    for member, key in (("memory.db", "db"),):
        digest = hashlib.sha256(first["before"][member]).hexdigest()
        assert value["snapshot"][key + "_sha256_before"] == digest
        assert value["snapshot"][key + "_sha256_after"] == digest
    assert value["schema"] == "continuityos.product_demo_person_continuity/v2"
    assert value["work_order"] == "COS_PERSON_CONTINUITY_DURABLE_DEMO_R2"
    assert value["snapshot"]["admission_source"] == "MEMORY_SQLITE"
    assert value["snapshot"]["admission_sidecar_count"] == 0
    saved = fixture["context"]["admission_receipt"]
    saved_hash = hashlib.sha256(person_demo._canonical(saved)).hexdigest()
    assert a["stored_receipt_sha256"] == b["stored_receipt_sha256"] == saved_hash
    assert a["publication_id"] == b["publication_id"] == fixture["publication_id"]
    assert value["prepare"]["stored_receipt_sha256"] == saved_hash
    assert value["snapshot"]["stored_receipt_sha256"] == saved_hash
    assert "admission_receipt" not in value["prepare"]
    assert "admission_bytes" not in value["prepare"] and "context" not in value["prepare"]
    assert all(worker["checks"]["durable_receipt_recovered"] is True for worker in (a,b))
    for kind in ("candidate", "pointer"):
        persisted = fixture["admission_bytes"][kind + "_utf8"].encode("utf-8")
        assert value["snapshot"][kind + "_sha256"] == hashlib.sha256(persisted).hexdigest()
    assert value["temporary_path_removed"] is True
    assert value["effects"]["temporary_cleanup_pass"] is True
    for effect in ("user_memory_read", "user_memory_write", "network_effect", "external_model_call"):
        assert value["effects"][effect] is False
    assert value["socket_audit"]["scope"] == "fixture_and_model_children"
    assert value["production_admission_status"] == "NOT_PRODUCTION_ADMITTED"
    assert value["execution_authority"] == "NONE" and value["can_execute"] is False


def test_person_demo_shows_recovered_work_context_and_routes_json(
    completed_person_demo, monkeypatch, capsys,
):
    value, observations = completed_person_demo
    text = observations[1]["fixture"]["context"]["source_record"]["payload"]["text"]
    rendered = person_demo.render_person_continuity(value)
    for key, label in (("goal", "Goal"), ("decision", "Decision"),
                       ("constraint", "Constraint"), ("next_action", "Next step")):
        persisted_value = next(line.split(": ", 1)[1] for line in text.splitlines()
                               if line.startswith(label + ": "))
        assert value["recovered"][key] == persisted_value
        assert persisted_value in rendered
    assert value["snapshot"]["memory_ref"] in rendered
    assert "External AI   NOT USED" in rendered
    assert "NOT_PRODUCTION_ADMITTED" in rendered
    seen = []

    def reuse_observed_result(*, timeout):
        seen.append(timeout)
        return copy.deepcopy(value), 0

    monkeypatch.setattr(person_demo, "run_person_continuity", reuse_observed_result)
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: (None, []))
    code = current_entrypoints.cos_main(["demo", "person-continuity", "--json", "--timeout", "7"])

    assert code == 0 and seen == [7.0]
    assert json.loads(capsys.readouterr().out) == value


@pytest.mark.parametrize("placement", ["leading", "trailing"])
def test_person_demo_rejects_user_db_before_any_demo_io(
    tmp_path, monkeypatch, capsys, placement,
):
    user_db = tmp_path / "user-memory.db"
    user_db.write_bytes(b"synthetic-user-memory-sentinel")
    before = user_db.read_bytes()

    def forbidden(*args, **kwargs):
        raise AssertionError("A public --db argument must stop before demo or DB resolution")

    monkeypatch.setattr(person_demo, "run_person_continuity", forbidden)
    monkeypatch.setattr(db, "resolve_memory_db", forbidden)
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: (None, []))
    args = ["demo", "person-continuity", "--json"]
    if placement == "leading":
        args = ["--db", str(user_db), *args]
    else:
        args.extend(["--db", str(user_db)])

    code = current_entrypoints.cos_main(args)
    value = json.loads(capsys.readouterr().out)

    _assert_hold(value, code)
    assert value["reason"] == "USER_DB_ARGUMENT_NOT_ALLOWED"
    assert value["effects"]["ephemeral_filesystem_write"] is False
    assert value["effects"]["ephemeral_memory_write"] is False
    assert value["effects"]["subprocess_execution"] is False
    assert user_db.read_bytes() == before


def test_person_demo_stays_inside_current_entrypoint_containment(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("A current-bound session must not enter the product demo")

    monkeypatch.setattr(person_demo, "run_person_continuity", forbidden)
    monkeypatch.setattr(
        current_entrypoints,
        "current_binding_from_env",
        lambda env: ({"challenge": "x", "ack": "y", "challenge_sha256": "z"}, []),
    )
    monkeypatch.setattr(
        current_entrypoints,
        "_verify_binding",
        lambda binding, surface, command: (
            {
                "binding_verified": True,
                "authority_generation": "R64",
                "challenge_id": "synthetic-demo-containment",
                "challenge_sha256": "a" * 64,
            },
            None,
        ),
    )

    assert current_entrypoints.cos_main(["demo", "person-continuity", "--json"]) == 3


@pytest.mark.parametrize("surface", ["runner", "worker", "private-cli"])
def test_person_demo_direct_surfaces_reject_declared_current_binding(
    tmp_path, monkeypatch, capsys, surface,
):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("forbidden-io")
        raise AssertionError("Current binding must stop before fixture access or subprocess work")

    monkeypatch.setenv("CONTINUITYOS_CURRENT_SESSION_REQUIRED", "1")
    monkeypatch.setattr(person_demo.tempfile, "mkdtemp", forbidden)
    monkeypatch.setattr(person_demo, "_run_process", forbidden)
    monkeypatch.setattr(person_demo, "_read_fixture", forbidden)
    monkeypatch.setattr(person_demo, "_install_child_socket_guard", forbidden)
    if surface == "runner":
        value, code = person_demo.run_person_continuity()
    elif surface == "worker":
        value, code = person_demo._worker(
            tmp_path / "continuityos-person-demo-unopened", "a" * 64, "B",
        )
    else:
        code = person_demo.main([
            "_worker", "--root", str(tmp_path / "continuityos-person-demo-unopened"),
            "--db-sha256", "a" * 64, "--role", "B",
        ])
        value = json.loads(capsys.readouterr().out)

    _assert_hold(value, code)
    assert "CURRENT" in value["reason"]
    assert not calls


@pytest.mark.parametrize("drift", ["stale-session", "revoked-consent", "stale-request"])
@pytest.mark.parametrize("boundary", [1, 2])
def test_person_demo_fresh_host_drift_holds_before_model(tmp_path, monkeypatch, drift, boundary):
    root, written = _fixture(tmp_path)
    original_read = person_demo._FixtureProvider.read_context
    seen = []

    def drifted_read(provider):
        context = original_read(provider)
        seen.append(drift)
        if provider.reads < boundary:
            return context
        if drift == "stale-session":
            context["current_session"] = copy.deepcopy(context["current_session"])
            context["current_session"]["challenge_sha256"] = "0" * 64
        elif drift == "stale-request":
            context["authorization_request"]["request_id"] = "stale-request"
        else:
            identity = context["identity"]
            consent = context["consent_receipt"]
            revocation = build_consent_revocation_entry(
                identity, consent,
                revoking_principal=identity["controller_id"],
                revoking_principal_kind=identity["controller_kind"],
                revoked_at=consent["issued_at"],
                reason="synthetic current consent revoked before Person READ",
            )
            context["current_revocation_ledger"] = build_consent_revocation_ledger([revocation])
        return context

    monkeypatch.setattr(person_demo._FixtureProvider, "read_context", drifted_read)
    value, code = person_demo._worker(root, written["db_sha256"], "B", written["run_id"])

    _assert_hold(value, code)
    assert value["model_calls"] == 0
    assert seen


@pytest.mark.parametrize("case", ["tampered-db", "injected-sidecar", "missing-db"])
def test_person_demo_changed_persisted_bytes_hold_without_reseed(tmp_path, monkeypatch, case):
    root, written = _fixture(tmp_path)
    member = "fixture.json" if case == "injected-sidecar" else "memory.db"
    path = root / member
    writer_calls = []

    def forbidden_writer(*args, **kwargs):
        writer_calls.append("reseed")
        raise AssertionError("B must consume persisted bytes without invoking a fixture writer")

    monkeypatch.setattr(person_demo, "_write_fixture", forbidden_writer)
    if case == "missing-db":
        path.unlink()
        changed = None
    elif case == "injected-sidecar":
        changed = b'{"admission_receipt":{"state":"CURRENT"}}'
        path.write_bytes(changed)
    else:
        # Keep the SQLite header intact and JSON parseable; the persisted hash
        # binding must reject changed bytes before model or mutable DB work.
        changed = path.read_bytes() + (b" " if member.endswith("json") else b"\x00")
        path.write_bytes(changed)

    value, code = person_demo._worker(root, written["db_sha256"], "B", written["run_id"])

    _assert_hold(value, code)
    assert value["model_calls"] == 0
    assert not writer_calls
    if changed is None:
        assert not path.exists()
    else:
        assert path.read_bytes() == changed


def test_person_demo_worker_uses_only_the_explicit_read_only_fixture(tmp_path, monkeypatch):
    from continuityos import sovereign_twin_runtime

    root, written = _fixture(tmp_path)
    user_db = tmp_path / "user-memory.db"
    user_db.write_bytes(b"synthetic-normal-db-sentinel")
    before = (root / "memory.db").read_bytes()
    opened = []
    original_runtime = sovereign_twin_runtime.SovereignTwinRuntime

    def observe_runtime(*args, **kwargs):
        runtime = original_runtime(*args, **kwargs)
        connection = runtime.memory.store.con
        opened.append((connection.execute("PRAGMA database_list").fetchone()[2],
                       connection.execute("PRAGMA query_only").fetchone()[0]))
        return runtime

    def forbidden_resolver(*args, **kwargs):
        raise AssertionError("The fixed synthetic worker must not resolve a normal DB")

    monkeypatch.setenv("CONTINUITYOS_DB", str(user_db))
    monkeypatch.setattr(db, "resolve_memory_db", forbidden_resolver)
    monkeypatch.setattr(sovereign_twin_runtime, "SovereignTwinRuntime", observe_runtime)

    value, code = person_demo._worker(root, written["db_sha256"], "B", written["run_id"])

    assert code == 0, value
    assert value["model_calls"] == 1 and value["transport"] == "cold_streaming"
    assert len(opened) == 1
    assert Path(opened[0][0]).resolve() == (root / "memory.db").resolve()
    assert opened[0][1] == 1
    assert (root / "memory.db").read_bytes() == before
    assert user_db.read_bytes() == b"synthetic-normal-db-sentinel"


def test_person_demo_rejects_linked_db_before_following_it(tmp_path):
    root, written = _fixture(tmp_path)
    path = root / "memory.db"
    outside = tmp_path / "outside-fixture-memory.db"
    before = path.read_bytes()
    outside.write_bytes(before)
    path.unlink()
    try:
        path.symlink_to(outside)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Creating a real filesystem symlink is unavailable: {type(exc).__name__}")

    value, code = person_demo._worker(root, written["db_sha256"], "B", written["run_id"])

    _assert_hold(value, code)
    assert value["reason"] == "FIXTURE_LINK_FORBIDDEN"
    assert value["model_calls"] == 0
    assert outside.read_bytes() == before


def test_person_demo_rejects_parent_traversal_even_to_valid_fixture(tmp_path):
    root, written = _fixture(tmp_path)
    redundant = tmp_path / "redundant-component"
    redundant.mkdir()
    traversal = redundant / ".." / root.name

    value, code = person_demo._worker(traversal, written["db_sha256"], "B", written["run_id"])

    _assert_hold(value, code)
    assert value["reason"] == "FIXTURE_ROOT_INVALID"
    assert value["model_calls"] == 0


@pytest.mark.parametrize("mutation", ["subset-checks", "corrupt-inner-hash", "stored-receipt", "publication", "sidecar", "source", "bool-calls"])
def test_person_demo_sealed_outer_receipt_does_not_replace_worker_validation(
    completed_person_demo, mutation,
):
    _, observations = completed_person_demo
    observed = observations[0]
    result = copy.deepcopy(observed["result"])
    fixture = observed["fixture"]
    fixture_sha = hashlib.sha256(observed["before"]["memory.db"]).hexdigest()
    assert person_demo._valid_worker(result, "A", fixture, fixture_sha) is True
    receipt = result["receipt"]
    if mutation == "subset-checks":
        receipt["checks"] = {"one_generation": True}
    elif mutation == "corrupt-inner-hash":
        receipt["person_evidence"]["receipt_hash"] = "0" * 64
    elif mutation == "stored-receipt":
        receipt["stored_receipt_sha256"] = "0" * 64
    elif mutation == "publication":
        receipt["publication_id"] = "0" * 32
    elif mutation == "sidecar":
        receipt["admission_sidecar_count"] = 1
    elif mutation == "source":
        receipt["admission_source"] = "SIDECAR"
    else:
        receipt["model_calls"] = True
    receipt.pop("receipt_sha256")
    result["receipt"] = person_demo._seal(receipt)

    assert person_demo._valid_worker(result, "A", fixture, fixture_sha) is False


@pytest.mark.parametrize("failure", ["timeout", "output-limit"])
def test_person_demo_process_limits_reap_the_actual_direct_child(monkeypatch, failure):
    created = []
    original_popen = subprocess.Popen

    def record_child(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        created.append(child)
        return child

    monkeypatch.setattr(person_demo.subprocess, "Popen", record_child)
    if failure == "timeout":
        command = [sys.executable, "-c", "import time; time.sleep(10)"]
        timeout = 0.1
    else:
        command = [sys.executable, "-c",
                   "import sys; sys.stdout.buffer.write(b'x' * 131072); sys.stdout.flush()"]
        timeout = 5.0
    try:
        result = person_demo._run_process(command, timeout)
        assert len(created) == 1
        assert created[0].poll() is not None
        assert result["process_id"] == created[0].pid
        assert result["started"] is True and result["direct_child_reaped"] is True
        assert len(result["stdout"]) <= person_demo.MAX_OUTPUT_BYTES
        assert len(result["stderr"]) <= person_demo.MAX_OUTPUT_BYTES
        if failure == "timeout":
            assert result["timed_out"] is True and result["kill_attempted"] is True
            assert result["returncode"] != 0
        else:
            assert result["output_limit_exceeded"] is True
    finally:
        # A failing reap assertion must not leave the test's owned child alive.
        for child in created:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3.0)


@pytest.mark.parametrize("failure", ["timeout", "output-limit", "unreaped"])
def test_person_demo_failed_process_cannot_reuse_a_valid_allow_receipt(
    completed_person_demo, monkeypatch, failure,
):
    value, _ = completed_person_demo
    raw = json.dumps(value["sessions"]["A"], ensure_ascii=False,
                     sort_keys=True, separators=(",", ":")).encode("utf-8")
    result = {
        "started": True, "returncode": 0, "process_id": value["sessions"]["A"]["process_id"],
        "direct_child_reaped": failure != "unreaped", "timed_out": failure == "timeout",
        "output_limit_exceeded": failure == "output-limit", "stdout": raw, "stderr": b"",
    }
    monkeypatch.setattr(person_demo, "_run_process", lambda command, timeout: dict(result))

    observed = person_demo._child_result(["synthetic-never-executed"], 1.0)

    assert observed["ok"] is False


@pytest.mark.parametrize("raw", [
    b"{not-json",
    b'{"number":1e999,"receipt_sha256":"' + b"a" * 64 + b'"}',
])
def test_person_demo_malformed_child_json_is_a_failed_result(monkeypatch, raw):
    monkeypatch.setattr(person_demo, "_run_process", lambda command, timeout: {
        "started": True, "returncode": 0, "direct_child_reaped": True,
        "timed_out": False, "output_limit_exceeded": False,
        "stdout": raw, "stderr": b"",
    })

    observed = person_demo._child_result(["synthetic-never-executed"], 1.0)

    assert observed["ok"] is False


def test_person_demo_invalid_worker_receipt_stops_before_b_and_cleans(tmp_path, monkeypatch):
    root = _controlled_root(tmp_path, monkeypatch)
    roles = []

    def incomplete_worker(root, expected_sha256, role, timeout, run_id):
        roles.append(role)
        return {
            "ok": True, "started": True, "returncode": 0, "direct_child_reaped": True,
            "receipt": {"schema": person_demo.WORKER_SCHEMA, "terminal": "PERSON_DEMO_WORKER_PASS"},
        }

    monkeypatch.setattr(person_demo, "_run_worker", incomplete_worker)
    value, code = person_demo._controller(timeout=20.0)

    _assert_hold(value, code)
    assert value["reason"] == "WORKER_RESULT_INVALID"
    assert roles == ["A"]
    assert value["temporary_path_removed"] is True
    assert not root.exists()


def test_person_demo_cleanup_failure_cannot_return_pass(tmp_path, monkeypatch):
    root = _controlled_root(tmp_path, monkeypatch)
    original_rmtree = shutil.rmtree

    def fail_cleanup(*args, **kwargs):
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(person_demo.shutil, "rmtree", fail_cleanup)
    try:
        value, code = person_demo._controller(timeout=20.0)

        _assert_hold(value, code)
        assert value["reason"] == "TEMPORARY_CLEANUP_FAILED"
        assert value["checks"] and all(value["checks"].values())
        assert value["effects"]["child_launches"] == 3
        assert value["effects"]["temporary_cleanup_pass"] is False
        assert value["temporary_path_removed"] is False
        assert root.exists()
    finally:
        if root.exists():
            original_rmtree(root)


@pytest.mark.parametrize("damage", ["missing-schema", "wrong-version", "missing-current", "missing-publication",
    "missing-candidate", "corrupt-receipt", "rehashed-receipt", "pointer-hash", "text", "namespace", "superseded"])
def test_durable_demo_rejects_structural_damage_even_with_recomputed_db_digest(tmp_path, monkeypatch, damage):
    from continuityos.person_twin_admission_store import PersonTwinAdmissionStore
    from continuityos.person_twin_admission_coordinator import PersonTwinAdmissionCoordinator
    root, written = _fixture(tmp_path)
    path = root / "memory.db"
    with sqlite3.connect(path) as con:
        if damage == "missing-schema":
            con.execute("DROP TABLE person_admission_meta")
        elif damage == "wrong-version":
            con.execute("UPDATE person_admission_meta SET schema_id='unknown'")
        elif damage == "missing-current":
            con.execute("DELETE FROM person_admission_current")
        elif damage == "missing-publication":
            con.execute("DELETE FROM person_admission_publications")
        elif damage == "missing-candidate":
            con.execute("DELETE FROM person_admission_candidates")
        elif damage == "corrupt-receipt":
            con.execute("UPDATE person_admission_publications SET receipt=?", (b"{}",))
        elif damage == "rehashed-receipt":
            con.execute("UPDATE person_admission_publications SET receipt=?,receipt_hash=?", (b"{}", hashlib.sha256(b"{}").hexdigest()))
        elif damage == "pointer-hash":
            con.execute("UPDATE person_admission_current SET pointer_hash=?", ("0" * 64,))
        elif damage == "text":
            con.execute("UPDATE items SET text='ALTERED_CURRENT_TEXT' WHERE id=?", (written["memory_id"],))
        elif damage == "namespace":
            con.execute("UPDATE items SET namespace='foreign-person' WHERE id=?", (written["memory_id"],))
        else:
            row = con.execute("SELECT meta FROM items WHERE id=?", (written["memory_id"],)).fetchone()
            meta = json.loads(row[0]); meta["superseded_by"] = 99999
            con.execute("UPDATE items SET meta=? WHERE id=?", (json.dumps(meta), written["memory_id"]))
    con.close()
    before = path.read_bytes()
    calls = []
    def forbidden(*args, **kwargs):
        calls.append("repair")
        raise AssertionError("Read must not repair or regenerate admission")
    monkeypatch.setattr(PersonTwinAdmissionStore, "initialize", forbidden)
    monkeypatch.setattr(PersonTwinAdmissionStore, "admit", forbidden)
    monkeypatch.setattr(PersonTwinAdmissionCoordinator, "promote_current", forbidden)
    monkeypatch.setattr(person_demo, "_write_fixture", forbidden)
    value, code = person_demo._worker(root, hashlib.sha256(before).hexdigest(), "B", written["run_id"])
    _assert_hold(value, code)
    assert value["model_calls"] == 0 and not calls
    assert path.read_bytes() == before
    assert {item.name for item in root.iterdir()} == {"memory.db"}


def test_durable_demo_expected_identity_is_not_selected_from_database(tmp_path):
    root, written = _fixture(tmp_path)
    before = (root / "memory.db").read_bytes()
    value, code = person_demo._worker(root, written["db_sha256"], "B", "f" * 32)
    _assert_hold(value, code)
    assert value["model_calls"] == 0
    assert (root / "memory.db").read_bytes() == before


@pytest.mark.parametrize("damage", ["full-receipt", "extra-context", "bool-memory-id", "bool-sidecars"])
def test_durable_demo_prepare_shape_cannot_transport_admission_payload(completed_person_demo, tmp_path, monkeypatch, damage):
    value, observations = completed_person_demo
    prepared = {**value["processes"][0], "receipt": copy.deepcopy(value["prepare"]), "ok": True}
    assert person_demo._valid_preparation(prepared, value["run_id"]) is True
    def invalid_prepare(root, run_id, timeout):
        result = copy.deepcopy(prepared)
        receipt = result["receipt"]
        receipt["run_id"] = run_id
        if damage == "full-receipt":
            receipt["admission_receipt"] = observations[0]["fixture"]["context"]["admission_receipt"]
        elif damage == "extra-context":
            receipt["context"] = observations[0]["fixture"]["context"]
        elif damage == "bool-memory-id":
            receipt["memory_id"] = True
        else:
            receipt["admission_sidecar_count"] = False
        receipt.pop("receipt_sha256")
        result["receipt"] = person_demo._seal(receipt)
        return result
    def forbidden_worker(*args, **kwargs):
        raise AssertionError("Invalid PREPARE cannot reach a model worker")
    root = _controlled_root(tmp_path, monkeypatch)
    monkeypatch.setattr(person_demo, "_run_prepare", invalid_prepare)
    monkeypatch.setattr(person_demo, "_run_worker", forbidden_worker)
    outcome, code = person_demo.run_person_continuity()
    _assert_hold(outcome, code)
    assert outcome["reason"] == "FIXTURE_PREPARATION_RECEIPT_INVALID"
    assert not root.exists()


def test_durable_demo_db_tampering_between_real_workers_stops_b(tmp_path, monkeypatch):
    root = _controlled_root(tmp_path, monkeypatch)
    original = person_demo._run_worker
    observations = []
    def change_before_b(root, digest, role, timeout, run_id):
        if role == "B":
            with sqlite3.connect(root / "memory.db") as con:
                con.execute("UPDATE person_admission_publications SET receipt=?", (b"{}",))
            con.close()
        result = original(root, digest, role, timeout, run_id)
        observations.append(result)
        return result
    monkeypatch.setattr(person_demo, "_run_worker", change_before_b)
    value, code = person_demo.run_person_continuity()
    _assert_hold(value, code)
    assert value["reason"] == "WORKER_RESULT_INVALID"
    assert len(observations) == 2
    assert observations[0]["receipt"]["model_calls"] == 1
    assert observations[1]["receipt"]["model_calls"] == 0
    assert observations[1]["direct_child_reaped"] is True
    assert not root.exists()
