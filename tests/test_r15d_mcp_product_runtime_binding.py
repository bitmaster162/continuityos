from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

import continuityos.mcp_server as mcp_server
from continuityos.gate.broker import GateBroker
from continuityos.gate.monotonic_anchor import (
    BoundMonotonicAnchorProfile,
    MonotonicExecutionAnchor,
)
from continuityos.gate.windows_tpm_product_runtime import (
    WindowsTpmProductRuntimeError,
    build_windows_r15_monotonic_anchor,
)
from continuityos.gate.windows_tpm_provisioning import build_reviewed_plan
from continuityos.memory import Memory


EK_SHA256 = "d4493341ea776e196234af9547d2a22118767eea3a0312d00e445fa497f6469c"


def _policy(path: Path) -> None:
    path.write_text(json.dumps({"default_decision": "ALLOW"}), encoding="utf-8")


def _memory(path: Path) -> None:
    memory = Memory(str(path))
    memory.store.con.close()


def _controller_and_custody(tmp_path: Path):
    plan = build_reviewed_plan(ek_public_sha256=EK_SHA256)
    controller = tmp_path / "controller.json"
    controller_raw = json.dumps(
        plan.active_profile.binding_document(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    controller.write_bytes(controller_raw)
    custody = tmp_path / "custody.json"
    custody.write_text(
        json.dumps(
            {
                "schema": "continuityos.r15b.windows-dpapi-index-auth/v1",
                "provider": "WINDOWS_DPAPI_CURRENT_USER",
                "nv_index": plan.nv_index,
                "ek_public_sha256": EK_SHA256,
                "ciphertext_b64": base64.b64encode(b"encrypted").decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )
    return plan, controller, hashlib.sha256(controller_raw).hexdigest(), custody


class _ReadOnlyBackend:
    def __init__(self, store, plan):
        self.store = store
        self.plan = plan
        self.reads = 0

    def read_snapshot(self, *, profile):
        self.reads += 1
        public = self.plan.active_public
        return {
            "nv_index": self.plan.nv_index,
            "tpma_nv_mask": self.plan.active_mask,
            "auth_policy_sha256": None,
            "backend_kind": profile.constraints.backend_kind,
            "transport_identity": profile.constraints.transport_identity,
            "nv_type": "TPM_NT_EXTEND",
            "name_alg": "SHA256",
            "data_size": 32,
            "orderly": False,
            "tpms_nv_public_marshaled": public,
            "raw_tpm_name": b"\x00\x0b" + hashlib.sha256(public).digest(),
            "observed_nv_extend_digest": "a" * 64,
        }

    def extend_once(self, **_kwargs):
        raise AssertionError("R15D startup must never extend TPM state")


def test_explicit_runtime_factory_is_readonly_and_pinned(tmp_path):
    plan, controller, controller_sha, custody = _controller_and_custody(tmp_path)
    backends = []

    def factory(store):
        backend = _ReadOnlyBackend(store, plan)
        backends.append(backend)
        return backend

    anchor = build_windows_r15_monotonic_anchor(
        controller_profile_path=str(controller),
        controller_profile_sha256=controller_sha,
        custody_path=str(custody),
        backend_factory=factory,
    )

    assert len(backends) == 1
    assert backends[0].reads == 1
    assert anchor.provider.read_snapshot()["observed_digest"] == "a" * 64
    assert backends[0].reads == 2


def test_runtime_factory_rejects_controller_pin_mismatch_before_backend(tmp_path):
    _plan, controller, _controller_sha, custody = _controller_and_custody(tmp_path)
    called = False

    def factory(_store):
        nonlocal called
        called = True
        raise AssertionError("backend must not be constructed after pin mismatch")

    with pytest.raises(
        WindowsTpmProductRuntimeError,
        match="controller profile SHA-256 differs",
    ):
        build_windows_r15_monotonic_anchor(
            controller_profile_path=str(controller),
            controller_profile_sha256="0" * 64,
            custody_path=str(custody),
            backend_factory=factory,
        )
    assert called is False


class _FakeProvider:
    def __init__(self):
        self.digest = "0" * 64
        self.extend_calls = 0

    def read_snapshot(self):
        return {
            "provider": "TPM2_NV_EXTEND",
            "nv_public_sha256": "1" * 64,
            "nv_name_sha256": "2" * 64,
            "observed_digest": self.digest,
        }

    def extend(self, *, expected_previous_digest, commitment_sha256):
        assert self.digest == expected_previous_digest
        self.extend_calls += 1
        self.digest = hashlib.sha256(
            bytes.fromhex(self.digest) + bytes.fromhex(commitment_sha256)
        ).hexdigest()
        return self.read_snapshot()


def _activated_product_state(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    root = home / ".continuityos"
    root.mkdir()
    paths = {
        "registry_path": str(root / "gate_broker.db"),
        "ledger_path": str(root / "ledger.db"),
        "witness_path": str(tmp_path / "external" / "witness.json"),
    }
    r14 = GateBroker(**paths)
    provider = _FakeProvider()
    profile = BoundMonotonicAnchorProfile(
        nv_public_sha256="1" * 64,
        nv_name_sha256="2" * 64,
        genesis_digest="0" * 64,
    )
    anchor = MonotonicExecutionAnchor(provider, profile=profile)
    with r14._ledger() as ledger:
        anchor.bind_genesis(ledger)
        before = ledger.frontier()
    db = tmp_path / "memory.db"
    policy = tmp_path / "policy.json"
    _memory(db)
    _policy(policy)
    return home, paths, anchor, db, policy, before


def test_product_startup_and_restart_inject_existing_r15_anchor(
    tmp_path, monkeypatch
):
    _home, paths, anchor, db, policy, before = _activated_product_state(
        tmp_path, monkeypatch
    )
    calls = []

    def build(**kwargs):
        calls.append(kwargs)
        return anchor

    monkeypatch.setattr(mcp_server, "_build_windows_r15_monotonic_anchor", build)
    common = dict(
        governance_witness_path=paths["witness_path"],
        r15_controller_profile_path=str(tmp_path / "controller.json"),
        r15_controller_profile_sha256="a" * 64,
        r15_custody_path=str(tmp_path / "custody.json"),
    )
    first = mcp_server.Server(str(db), str(policy), **common)
    first_broker = first._gate_broker()
    second = mcp_server.Server(str(db), str(policy), **common)
    second_broker = second._gate_broker()

    assert len(calls) == 2
    assert first_broker.monotonic_anchor is anchor
    assert second_broker.monotonic_anchor is anchor
    assert first_broker.witness.path == __import__("os").path.normcase(
        __import__("os").path.abspath(paths["witness_path"])
    )
    with second_broker._ledger() as ledger:
        assert ledger.frontier() == before
        assert anchor.validate_global(ledger)["anchor_generation"] == 1


def test_product_binding_mismatch_holds_without_ledger_write(
    tmp_path, monkeypatch
):
    _home, paths, _anchor, db, policy, before = _activated_product_state(
        tmp_path, monkeypatch
    )

    def fail(**_kwargs):
        raise WindowsTpmProductRuntimeError("hardware binding mismatch")

    monkeypatch.setattr(mcp_server, "_build_windows_r15_monotonic_anchor", fail)
    server = mcp_server.Server(
        str(db),
        str(policy),
        governance_witness_path=paths["witness_path"],
        r15_controller_profile_path=str(tmp_path / "controller.json"),
        r15_controller_profile_sha256="a" * 64,
        r15_custody_path=str(tmp_path / "custody.json"),
    )
    result = json.loads(server.call(
        "preflight_exec",
        {
            "request_id": "must-hold",
            "argv": ["cmd.exe", "/c", "exit", "0"],
            "cwd": str(tmp_path),
            "paths": [],
        },
    ))
    assert result["state"] == "HELD"
    assert any("hardware binding mismatch" in reason for reason in result["reasons"])
    with GateBroker(**paths, monotonic_anchor=_anchor)._ledger() as ledger:
        assert ledger.frontier() == before


def test_incomplete_explicit_r15_configuration_holds(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    db = tmp_path / "memory.db"
    policy = tmp_path / "policy.json"
    _memory(db)
    _policy(policy)
    server = mcp_server.Server(
        str(db),
        str(policy),
        governance_witness_path=str(tmp_path / "witness.json"),
        r15_controller_profile_path=str(tmp_path / "controller.json"),
    )
    result = json.loads(server.call(
        "preflight_exec",
        {
            "request_id": "incomplete",
            "argv": ["cmd.exe"],
            "cwd": str(tmp_path),
            "paths": [],
        },
    ))
    assert result["state"] == "HELD"
    assert any("configuration is incomplete" in reason for reason in result["reasons"])
