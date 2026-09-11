"""R15 hardware-free TPM2 monotonic execution-anchor acceptance tests."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from continuityos.gate import cli
from continuityos.gate.broker import GateBroker
from continuityos.gate.ledger import GENESIS, Ledger
from continuityos.gate.monotonic_anchor import (
    EVENT_KIND, PHASE_GENESIS, PHASE_STARTED, PHASE_TERMINAL,
    BoundMonotonicAnchorProfile, MonotonicAnchorError, MonotonicExecutionAnchor,
    UnprovisionedTpm2NvExtendProvider, _expected_digest,
)
from continuityos.gate.policy import default_policy
from continuityos.mcp_server import TOOLS


def _profile(provider):
    return BoundMonotonicAnchorProfile(
        nv_public_sha256=provider.nv_public_sha256,
        nv_name_sha256=provider.nv_name_sha256,
        genesis_digest=GENESIS,
    )


def _anchor(provider):
    return MonotonicExecutionAnchor(provider, profile=_profile(provider))


class FakeNvExtendProvider:
    def __init__(self):
        self.nv_public_sha256 = hashlib.sha256(b"r15-test-nv-public").hexdigest()
        self.nv_name_sha256 = hashlib.sha256(b"r15-test-nv-name").hexdigest()
        self.digest = GENESIS
        self.extend_calls = 0
        self.fail_before = set()
        self.fail_after = set()
        self.available = True

    def read_snapshot(self):
        if not self.available:
            raise RuntimeError("fake TPM unavailable")
        return {
            "provider": "TPM2_NV_EXTEND",
            "nv_public_sha256": self.nv_public_sha256,
            "nv_name_sha256": self.nv_name_sha256,
            "observed_digest": self.digest,
        }

    def extend(self, *, expected_previous_digest, commitment_sha256):
        next_call = self.extend_calls + 1
        if next_call in self.fail_before:
            raise RuntimeError("fake TPM extend failed before mutation")
        if expected_previous_digest != self.digest:
            raise RuntimeError("fake TPM compare-and-extend conflict")
        self.extend_calls = next_call
        self.digest = _expected_digest(self.digest, commitment_sha256)
        if next_call in self.fail_after:
            raise RuntimeError("fake TPM failed after irreversible extend")
        return self.read_snapshot()


def _allow(_self, _spec):
    policy = default_policy()
    policy["default_decision"] = "ALLOW"
    policy["severity_decision"] = {
        key: "ALLOW" for key in policy["severity_decision"]
    }
    policy["effect_decision"] = {
        key: "ALLOW" for key in policy["effect_decision"]
    }
    return policy, None


def _script(tmp_path, name="effect.py", output="effect.txt"):
    script = tmp_path / name
    script.write_text(
        "from pathlib import Path\n"
        f"p=Path({output!r})\n"
        "p.write_text((p.read_text() if p.exists() else '')+'x')\n",
        encoding="utf-8",
    )
    return script


def _preflight(broker, tmp_path, request_id="r15", *, script=None):
    script = script or _script(tmp_path)
    result = broker.preflight_exec(
        request_id, [sys.executable, str(script)], str(tmp_path), []
    )
    assert result["decision"] in ("ALLOW", "REQUIRE_CONFIRMATION"), result
    if result["decision"] == "REQUIRE_CONFIRMATION":
        with broker._ledger() as ledger:
            ledger.append("override", {
                "preflight_hash": result["preflight_hash"], "by": "human",
            })
    return result


@pytest.fixture
def r15(tmp_path, monkeypatch):
    cli._require_legacy_gate()
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    paths = {
        "registry_path": str(tmp_path / "registry.db"),
        "ledger_path": str(tmp_path / "ledger.db"),
        "witness_path": str(tmp_path / "r14" / "witness.json"),
    }
    r14 = GateBroker(**paths)
    provider = FakeNvExtendProvider()
    anchor = _anchor(provider)
    with r14._ledger() as ledger:
        activation = anchor.bind_genesis(ledger)
    assert activation["anchor_generation"] == 1
    assert provider.extend_calls == 1
    broker = GateBroker(**paths, monotonic_anchor=anchor)
    return {
        "broker": broker, "provider": provider, "anchor": anchor,
        "paths": paths, "tmp_path": tmp_path,
    }


def _checkpoint(path):
    with sqlite3.connect(path) as con:
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def _backup(source, destination):
    with sqlite3.connect(source) as src, sqlite3.connect(destination) as dst:
        src.backup(dst)


def test_happy_path_anchors_started_and_terminal_before_cached_retry(r15):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path)
    first = broker.execute_preflight("r15")
    assert first["state"] == "TERMINAL", first
    assert (tmp_path / "effect.txt").read_text() == "x"
    assert provider.extend_calls == 3

    cached = broker.execute_preflight("r15")
    assert cached["state"] == "CACHED", cached
    assert (tmp_path / "effect.txt").read_text() == "x"
    assert provider.extend_calls == 3

    with broker._ledger() as ledger:
        phases = [
            json.loads(row[0])["phase"]
            for row in ledger.con.execute(
                "SELECT payload FROM events WHERE kind=? ORDER BY id", (EVENT_KIND,)
            )
        ]
    assert phases == [PHASE_GENESIS, PHASE_STARTED, PHASE_TERMINAL]


def test_start_extend_failure_holds_before_subprocess(r15):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path)
    provider.fail_before.add(2)

    result = broker.execute_preflight("r15")
    assert result["state"] == "HELD", result
    assert not (tmp_path / "effect.txt").exists()
    assert provider.extend_calls == 1
    with broker._ledger() as ledger:
        attempt = ledger._validate_attempt_row(ledger._attempt_row(result["preflight_hash"]))
    assert attempt["phase"] == "ATTEMPT_STARTED"


def test_provider_unavailable_holds_before_claim_or_effect(r15):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    pre = _preflight(broker, tmp_path)
    provider.available = False
    result = broker.execute_preflight("r15")
    assert result["state"] == "HELD", result
    assert not (tmp_path / "effect.txt").exists()
    with broker._ledger() as ledger:
        assert ledger._attempt_row(pre["preflight_hash"]) is None


def test_irreversible_extend_then_local_receipt_failure_requires_offline_recovery(
    r15, monkeypatch
):
    broker = r15["broker"]
    provider = r15["provider"]
    anchor = r15["anchor"]
    tmp_path = r15["tmp_path"]
    paths = r15["paths"]
    _preflight(broker, tmp_path)
    real_append = Ledger.append

    def fail_started_anchor(self, kind, payload):
        if kind == EVENT_KIND and payload.get("phase") == PHASE_STARTED:
            raise OSError("injected local anchor receipt failure")
        return real_append(self, kind, payload)

    monkeypatch.setattr(Ledger, "append", fail_started_anchor)
    result = broker.execute_preflight("r15")
    assert result["state"] == "HELD", result
    assert not (tmp_path / "effect.txt").exists()
    assert provider.extend_calls == 2

    monkeypatch.setattr(Ledger, "append", real_append)
    with pytest.raises(MonotonicAnchorError, match="hardware frontier"):
        GateBroker(**paths, monotonic_anchor=anchor)


@pytest.mark.parametrize("after_irreversible", [False, True])
def test_terminal_anchor_failure_never_repeats_effect(r15, after_irreversible):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path)
    if after_irreversible:
        provider.fail_after.add(3)
    else:
        provider.fail_before.add(3)

    first = broker.execute_preflight("r15")
    assert first["state"] == "HELD", first
    assert (tmp_path / "effect.txt").read_text() == "x"
    first_count = provider.extend_calls

    second = broker.execute_preflight("r15")
    assert second["state"] == "HELD", second
    assert (tmp_path / "effect.txt").read_text() == "x"
    assert provider.extend_calls == first_count
    with broker._ledger() as ledger:
        attempt = ledger._validate_attempt_row(ledger._attempt_row(first["preflight_hash"]))
    assert attempt["phase"] == "TERMINAL"


def _restore(source, destination):
    _backup(source, destination)


def test_coherent_rollback_of_all_r14_files_is_detected_by_hardware_frontier(r15):
    broker = r15["broker"]
    tmp_path = r15["tmp_path"]
    paths = r15["paths"]
    _preflight(broker, tmp_path)
    _checkpoint(paths["ledger_path"])
    old_ledger = tmp_path / "old-ledger.db"
    old_registry = tmp_path / "old-registry.db"
    old_witness = tmp_path / "old-witness.json"
    _backup(paths["ledger_path"], old_ledger)
    _backup(paths["registry_path"], old_registry)
    shutil.copyfile(paths["witness_path"], old_witness)

    first = broker.execute_preflight("r15")
    assert first["state"] == "TERMINAL", first
    assert (tmp_path / "effect.txt").read_text() == "x"

    _checkpoint(paths["ledger_path"])
    _restore(old_ledger, paths["ledger_path"])
    _restore(old_registry, paths["registry_path"])
    shutil.copyfile(old_witness, paths["witness_path"])
    rolled = broker.execute_preflight("r15")
    assert rolled["state"] == "HELD", rolled
    assert any("hardware frontier" in reason for reason in rolled["reasons"])
    assert (tmp_path / "effect.txt").read_text() == "x"


def test_hardware_identity_substitution_holds_without_effect(r15):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path)
    provider.nv_public_sha256 = hashlib.sha256(b"substituted-nv").hexdigest()
    result = broker.execute_preflight("r15")
    assert result["state"] == "HELD", result
    assert any("identity substitution" in reason for reason in result["reasons"])
    assert not (tmp_path / "effect.txt").exists()


def test_concurrent_brokers_produce_one_effect_and_one_anchor_pair(r15):
    broker = r15["broker"]
    provider = r15["provider"]
    anchor = r15["anchor"]
    paths = r15["paths"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path)
    other = GateBroker(**paths, monotonic_anchor=anchor)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda b: b.execute_preflight("r15"), (broker, other)
        ))
    assert sorted(result["state"] for result in results) == ["CACHED", "TERMINAL"]
    assert (tmp_path / "effect.txt").read_text() == "x"
    assert provider.extend_calls == 3


def test_r15_requires_r14_witness(tmp_path):
    provider = FakeNvExtendProvider()
    anchor = _anchor(provider)
    with pytest.raises(ValueError, match="requires the R14 witness"):
        GateBroker(
            str(tmp_path / "registry.db"), str(tmp_path / "ledger.db"),
            monotonic_anchor=anchor,
        )


def test_genesis_binding_is_explicit_and_single_use(r15):
    broker = r15["broker"]
    anchor = r15["anchor"]
    with broker._ledger() as ledger:
        with pytest.raises(MonotonicAnchorError, match="already bound"):
            anchor.bind_genesis(ledger)


def test_unprovisioned_provider_has_no_hardware_fallback():
    provider = UnprovisionedTpm2NvExtendProvider()
    with pytest.raises(MonotonicAnchorError, match="unprovisioned"):
        provider.read_snapshot()
    with pytest.raises(MonotonicAnchorError, match="unprovisioned"):
        provider.extend(
            expected_previous_digest=GENESIS,
            commitment_sha256="1" * 64,
        )


def test_product_mcp_authority_is_not_widened_for_r15():
    by_name = {tool["name"]: tool["inputSchema"] for tool in TOOLS}
    assert set(by_name["execute_preflight"]["properties"]) == {"request_id"}
    assert set(by_name["preflight_exec"]["properties"]) == {
        "request_id", "argv", "cwd", "paths"
    }
    forbidden = (
        "anchor", "tpm", "nv_", "provision", "reset", "undefine", "extend"
    )
    for tool in TOOLS:
        assert not any(token in tool["name"].lower() for token in forbidden)


def test_hardware_digest_substitution_holds_without_effect(r15):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path)
    provider.digest = hashlib.sha256(b"impossible-local-rollback").hexdigest()
    result = broker.execute_preflight("r15")
    assert result["state"] == "HELD", result
    assert any("hardware frontier" in reason for reason in result["reasons"])
    assert not (tmp_path / "effect.txt").exists()


def test_subprocess_exception_is_terminal_anchored_and_cached(r15, monkeypatch):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path)

    def fail_call(*args, **kwargs):
        raise OSError("injected process creation failure")

    monkeypatch.setattr(cli.subprocess, "call", fail_call)
    first = broker.execute_preflight("r15")
    assert first["state"] == "TERMINAL", first
    assert first["terminal_kind"] == "execution_failed"
    assert provider.extend_calls == 3
    assert not (tmp_path / "effect.txt").exists()

    cached = broker.execute_preflight("r15")
    assert cached["state"] == "CACHED", cached
    assert cached["terminal_kind"] == "execution_failed"
    assert provider.extend_calls == 3


def test_external_nv_move_after_local_started_receipt_still_blocks_subprocess(
    r15, monkeypatch
):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path)
    real_append = Ledger.append
    moved = {"done": False}

    def append_then_external_move(self, kind, payload):
        receipt_hash = real_append(self, kind, payload)
        if kind == EVENT_KIND and payload.get("phase") == PHASE_STARTED and not moved["done"]:
            moved["done"] = True
            provider.digest = _expected_digest(provider.digest, "f" * 64)
        return receipt_hash

    monkeypatch.setattr(Ledger, "append", append_then_external_move)
    result = broker.execute_preflight("r15")
    assert result["state"] == "HELD", result
    assert moved["done"] is True
    assert not (tmp_path / "effect.txt").exists()


def test_missing_terminal_anchor_globally_blocks_new_preflight_until_reconciled(r15):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path)
    provider.fail_before.add(3)
    first = broker.execute_preflight("r15")
    assert first["state"] == "HELD", first
    assert (tmp_path / "effect.txt").read_text() == "x"

    next_script = _script(tmp_path, name="next.py", output="next.txt")
    blocked = broker.preflight_exec(
        "r15-next", [sys.executable, str(next_script)], str(tmp_path), []
    )
    assert blocked["state"] == "HELD", blocked
    assert any("offline monotonic reconciliation" in r for r in blocked["reasons"])
    assert not (tmp_path / "next.txt").exists()
    assert provider.extend_calls == 2


def test_activation_genesis_covers_historical_r14_terminal_attempts(tmp_path, monkeypatch):
    cli._require_legacy_gate()
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    paths = {
        "registry_path": str(tmp_path / "registry.db"),
        "ledger_path": str(tmp_path / "ledger.db"),
        "witness_path": str(tmp_path / "witness.json"),
    }
    r14 = GateBroker(**paths)
    _preflight(r14, tmp_path, "historical")
    first = r14.execute_preflight("historical")
    assert first["state"] == "TERMINAL", first
    assert (tmp_path / "effect.txt").read_text() == "x"

    provider = FakeNvExtendProvider()
    anchor = _anchor(provider)
    with r14._ledger() as ledger:
        activation = anchor.bind_genesis(ledger)
    assert activation["anchor_generation"] == 1
    r15_broker = GateBroker(**paths, monotonic_anchor=anchor)
    cached = r15_broker.execute_preflight("historical")
    assert cached["state"] == "CACHED", cached
    assert provider.extend_calls == 1
    assert (tmp_path / "effect.txt").read_text() == "x"


def test_activation_refuses_claimed_or_started_r14_attempt(tmp_path, monkeypatch):
    cli._require_legacy_gate()
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    paths = {
        "registry_path": str(tmp_path / "registry.db"),
        "ledger_path": str(tmp_path / "ledger.db"),
        "witness_path": str(tmp_path / "witness.json"),
    }
    r14 = GateBroker(**paths)
    pre = _preflight(r14, tmp_path, "active-before-r15")
    with r14._ledger() as ledger:
        event = ledger.event(pre["preflight_hash"])
        action = event["payload"]["action"]
        binding = cli._execution_binding_sha256(
            action["command"], "exec",
            {"action": action, "ledger_hash": pre["preflight_hash"]},
            list(action["args"]), execution_cwd=action["cwd"],
        )
        claim = ledger.claim_execution_attempt(
            preflight_hash=pre["preflight_hash"], binding_sha256=binding,
            expected_action=action,
            expected_rollback_plan=event["payload"]["rollback_plan"],
            expected_decision=event["payload"]["decision"],
        )
        assert claim["status"] == "CLAIMED_NEW"
        anchor = _anchor(FakeNvExtendProvider())
        with pytest.raises(MonotonicAnchorError, match="requires no claimed or started"):
            anchor.bind_genesis(ledger)


def test_unanchored_started_boundary_globally_blocks_after_anchor_failure(r15):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path, "missing-start-anchor")
    provider.fail_before.add(2)
    first = broker.execute_preflight("missing-start-anchor")
    assert first["state"] == "HELD", first
    assert not (tmp_path / "effect.txt").exists()

    next_script = _script(tmp_path, name="after-gap.py", output="after-gap.txt")
    blocked = broker.preflight_exec(
        "after-gap", [sys.executable, str(next_script)], str(tmp_path), []
    )
    assert blocked["state"] == "HELD", blocked
    assert any(
        "post-activation execution_started lacks monotonic receipt" in reason
        for reason in blocked["reasons"]
    )
    assert not (tmp_path / "after-gap.txt").exists()


def test_activation_receipt_loss_cannot_silently_reextend(tmp_path, monkeypatch):
    cli._require_legacy_gate()
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    paths = {
        "registry_path": str(tmp_path / "registry.db"),
        "ledger_path": str(tmp_path / "ledger.db"),
        "witness_path": str(tmp_path / "witness.json"),
    }
    r14 = GateBroker(**paths)
    provider = FakeNvExtendProvider()
    anchor = _anchor(provider)
    real_append = Ledger.append

    def lose_genesis_receipt(self, kind, payload):
        if kind == EVENT_KIND and payload.get("phase") == PHASE_GENESIS:
            raise OSError("injected activation receipt loss")
        return real_append(self, kind, payload)

    monkeypatch.setattr(Ledger, "append", lose_genesis_receipt)
    with r14._ledger() as ledger:
        with pytest.raises(MonotonicAnchorError, match="hardware advanced"):
            anchor.bind_genesis(ledger)
    assert provider.extend_calls == 1
    assert provider.digest != GENESIS
    monkeypatch.setattr(Ledger, "append", real_append)
    with r14._ledger() as ledger:
        with pytest.raises(MonotonicAnchorError, match="bound genesis digest"):
            anchor.bind_genesis(ledger)
    assert provider.extend_calls == 1


def test_bound_profile_blocks_identity_substitution_before_activation(tmp_path, monkeypatch):
    cli._require_legacy_gate()
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    paths = {
        "registry_path": str(tmp_path / "registry.db"),
        "ledger_path": str(tmp_path / "ledger.db"),
        "witness_path": str(tmp_path / "witness.json"),
    }
    r14 = GateBroker(**paths)
    provider = FakeNvExtendProvider()
    anchor = _anchor(provider)
    provider.nv_name_sha256 = hashlib.sha256(b"wrong-bound-nv-name").hexdigest()
    with r14._ledger() as ledger:
        with pytest.raises(MonotonicAnchorError, match="identity substitution"):
            anchor.bind_genesis(ledger)
    assert provider.extend_calls == 0


def test_direct_activation_requires_r14_witness_bound_ledger(tmp_path):
    provider = FakeNvExtendProvider()
    anchor = _anchor(provider)
    with Ledger(str(tmp_path / "legacy.db")) as ledger:
        with pytest.raises(MonotonicAnchorError, match="R14 witness-bound ledger"):
            anchor.bind_genesis(ledger)
    assert provider.extend_calls == 0


def test_started_anchor_without_terminal_receipt_globally_holds(r15, monkeypatch):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path, "terminal-db-loss")
    real_finish = Ledger.finish_execution_attempt

    def fail_terminal_commit(self, *args, **kwargs):
        raise OSError("injected terminal ledger commit failure")

    monkeypatch.setattr(Ledger, "finish_execution_attempt", fail_terminal_commit)
    first = broker.execute_preflight("terminal-db-loss")
    assert first["state"] == "HELD", first
    assert (tmp_path / "effect.txt").read_text() == "x"
    assert provider.extend_calls == 2

    monkeypatch.setattr(Ledger, "finish_execution_attempt", real_finish)
    next_script = _script(tmp_path, name="after-ambiguous.py", output="after-ambiguous.txt")
    blocked = broker.preflight_exec(
        "after-ambiguous", [sys.executable, str(next_script)], str(tmp_path), []
    )
    assert blocked["state"] == "HELD", blocked
    assert any("verified terminal outcome" in reason for reason in blocked["reasons"])
    assert not (tmp_path / "after-ambiguous.txt").exists()


def test_direct_cli_checks_r15_consistency_before_claim(r15, monkeypatch):
    broker = r15["broker"]
    provider = r15["provider"]
    anchor = r15["anchor"]
    tmp_path = r15["tmp_path"]
    preflight = _preflight(broker, tmp_path, "direct-cli-consistency")
    with broker._ledger() as ledger:
        event = ledger.event(preflight["preflight_hash"])
    payload = event["payload"]
    result = {
        "decision": payload["decision"],
        "action": payload["action"],
        "ledger_hash": preflight["preflight_hash"],
        "rollback_plan": payload["rollback_plan"],
    }
    provider.digest = hashlib.sha256(b"unexpected-hardware-frontier").hexdigest()
    calls = []
    monkeypatch.setattr(cli.subprocess, "call", lambda *a, **k: calls.append((a, k)) or 0)
    outcome = {}
    rc = cli._execute_approved(
        result["action"]["command"], "exec", result,
        argv=list(result["action"]["args"]), ledger_path=broker.ledger_path,
        execution_cwd=result["action"]["cwd"], witness_authority=broker.witness,
        monotonic_anchor=anchor, outcome=outcome,
    )
    assert rc == 1
    assert calls == []
    with broker._ledger() as ledger:
        assert ledger._attempt_row(preflight["preflight_hash"]) is None


def test_cross_process_brokers_share_one_monotonic_effect(tmp_path, monkeypatch):
    cli._require_legacy_gate()
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    paths = {
        "registry_path": str(tmp_path / "registry.db"),
        "ledger_path": str(tmp_path / "ledger.db"),
        "witness_path": str(tmp_path / "witness.json"),
    }
    digest_path = tmp_path / "fake-nv-digest.txt"
    digest_path.write_text(GENESIS, encoding="ascii")
    nv_public = hashlib.sha256(b"r15-cross-process-public").hexdigest()
    nv_name = hashlib.sha256(b"r15-cross-process-name").hexdigest()

    class FileProvider:
        def read_snapshot(self):
            return {
                "provider": "TPM2_NV_EXTEND",
                "nv_public_sha256": nv_public,
                "nv_name_sha256": nv_name,
                "observed_digest": digest_path.read_text(encoding="ascii"),
            }

        def extend(self, *, expected_previous_digest, commitment_sha256):
            current = digest_path.read_text(encoding="ascii")
            if current != expected_previous_digest:
                raise MonotonicAnchorError("fake cross-process CAS mismatch")
            updated = _expected_digest(current, commitment_sha256)
            digest_path.write_text(updated, encoding="ascii")
            return {**self.read_snapshot(), "observed_digest": updated}

    profile = BoundMonotonicAnchorProfile(
        nv_public_sha256=nv_public,
        nv_name_sha256=nv_name,
        genesis_digest=GENESIS,
    )
    r14 = GateBroker(**paths)
    parent_anchor = MonotonicExecutionAnchor(FileProvider(), profile=profile)
    with r14._ledger() as ledger:
        parent_anchor.bind_genesis(ledger)
    broker = GateBroker(**paths, monotonic_anchor=parent_anchor)
    _preflight(broker, tmp_path, "cross-process-r15")

    child = r'''
import hashlib, json, sys
from pathlib import Path
from continuityos.gate.broker import GateBroker
from continuityos.gate.monotonic_anchor import (
    BoundMonotonicAnchorProfile, MonotonicAnchorError,
    MonotonicExecutionAnchor, _expected_digest,
)
config = json.loads(sys.argv[1])
digest_path = Path(config["digest_path"])
class Provider:
    def read_snapshot(self):
        return {"provider":"TPM2_NV_EXTEND","nv_public_sha256":config["nv_public"],
                "nv_name_sha256":config["nv_name"],
                "observed_digest":digest_path.read_text(encoding="ascii")}
    def extend(self, *, expected_previous_digest, commitment_sha256):
        current = digest_path.read_text(encoding="ascii")
        if current != expected_previous_digest:
            raise MonotonicAnchorError("fake cross-process CAS mismatch")
        updated = _expected_digest(current, commitment_sha256)
        digest_path.write_text(updated, encoding="ascii")
        return {**self.read_snapshot(), "observed_digest":updated}
'''
    child += r'''
profile = BoundMonotonicAnchorProfile(
    nv_public_sha256=config["nv_public"], nv_name_sha256=config["nv_name"],
    genesis_digest="0" * 64,
)
anchor = MonotonicExecutionAnchor(Provider(), profile=profile)
broker = GateBroker(
    registry_path=config["registry_path"], ledger_path=config["ledger_path"],
    witness_path=config["witness_path"], monotonic_anchor=anchor,
)
print(json.dumps(broker.execute_preflight("cross-process-r15"), sort_keys=True))
'''
    config = json.dumps({
        **paths,
        "digest_path": str(digest_path),
        "nv_public": nv_public,
        "nv_name": nv_name,
    })
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", child, config], cwd=os.getcwd(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(2)
    ]
    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=60)
        assert process.returncode == 0, stderr
        results.append(json.loads(stdout.strip().splitlines()[-1]))
    assert sorted(result["state"] for result in results) == ["CACHED", "TERMINAL"]
    assert (tmp_path / "effect.txt").read_text(encoding="utf-8") == "x"


def test_r15_activation_blocks_new_r14_only_broker(r15):
    with pytest.raises(ValueError, match="R15-activated governance state"):
        GateBroker(**r15["paths"])


def test_r15_activation_blocks_existing_r14_broker_preflight(tmp_path, monkeypatch):
    cli._require_legacy_gate()
    monkeypatch.setattr(GateBroker, "_load_adapter", _allow)
    paths = {
        "registry_path": str(tmp_path / "registry.db"),
        "ledger_path": str(tmp_path / "ledger.db"),
        "witness_path": str(tmp_path / "witness.json"),
    }
    legacy = GateBroker(**paths)
    provider = FakeNvExtendProvider()
    anchor = _anchor(provider)
    with legacy._ledger() as ledger:
        anchor.bind_genesis(ledger)
    script = _script(tmp_path, name="legacy-bypass.py", output="legacy-bypass.txt")
    blocked = legacy.preflight_exec(
        "legacy-r14-bypass", [sys.executable, str(script)], str(tmp_path), []
    )
    assert blocked["state"] == "HELD", blocked
    assert any("R15-activated governance state" in reason for reason in blocked["reasons"])
    assert not (tmp_path / "legacy-bypass.txt").exists()


def test_r15_activation_blocks_direct_cli_without_anchor(r15, monkeypatch):
    broker = r15["broker"]
    tmp_path = r15["tmp_path"]
    pre = _preflight(broker, tmp_path, "direct-r14-bypass")
    with broker._ledger() as ledger:
        event = ledger.event(pre["preflight_hash"])
    payload = event["payload"]
    result = {
        "decision": payload["decision"],
        "action": payload["action"],
        "ledger_hash": pre["preflight_hash"],
        "rollback_plan": payload["rollback_plan"],
    }
    calls = []
    monkeypatch.setattr(cli.subprocess, "call", lambda *a, **k: calls.append((a, k)) or 0)
    rc = cli._execute_approved(
        result["action"]["command"], "exec", result,
        argv=list(result["action"]["args"]), ledger_path=broker.ledger_path,
        execution_cwd=result["action"]["cwd"], witness_authority=broker.witness,
    )
    assert rc == 1
    assert calls == []
    with broker._ledger() as ledger:
        assert ledger._attempt_row(pre["preflight_hash"]) is None


def test_started_extend_failure_after_irreversible_advance_blocks_effect(r15):
    broker = r15["broker"]
    provider = r15["provider"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path, "started-after-extend-failure")
    provider.fail_after.add(2)
    first = broker.execute_preflight("started-after-extend-failure")
    assert first["state"] == "HELD", first
    assert not (tmp_path / "effect.txt").exists()
    assert provider.extend_calls == 2
    second = broker.execute_preflight("started-after-extend-failure")
    assert second["state"] == "HELD", second
    assert not (tmp_path / "effect.txt").exists()
    assert provider.extend_calls == 2


def test_terminal_anchor_replay_is_rejected_without_second_extend(r15):
    broker = r15["broker"]
    provider = r15["provider"]
    anchor = r15["anchor"]
    tmp_path = r15["tmp_path"]
    _preflight(broker, tmp_path, "terminal-replay")
    first = broker.execute_preflight("terminal-replay")
    assert first["state"] == "TERMINAL", first
    before = provider.extend_calls
    with broker._ledger() as ledger:
        attempt = ledger._validate_attempt_row(ledger._attempt_row(first["preflight_hash"]))
        with pytest.raises(MonotonicAnchorError, match="already monotonic-anchored"):
            anchor.record_execution_terminal(
                ledger, preflight_hash=first["preflight_hash"],
                binding_sha256=attempt["binding_sha256"],
                terminal_hash=attempt["terminal_hash"],
                terminal_kind=attempt["terminal_kind"],
            )
    assert provider.extend_calls == before
    assert (tmp_path / "effect.txt").read_text() == "x"
