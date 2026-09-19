from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

import continuityos.witnessed_approval_replay as replay


ROOT = Path(__file__).resolve().parents[1]

if not (
    (ROOT / "tools" / "r25_witness_service.py").is_file()
    and (ROOT / "tools" / "r25_replay_qualification.py").is_file()
):
    pytest.skip(
        "R25 qualification tools are repository-only and not packaged in the wheel",
        allow_module_level=True,
    )


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


witness_service = _load(
    "_r25_witness_service", ROOT / "tools" / "r25_witness_service.py"
)
qualification = _load(
    "_r25_replay_qualification", ROOT / "tools" / "r25_replay_qualification.py"
)


def _record(namespace: str) -> dict:
    return replay._build_record(
        namespace=namespace,
        generation=1,
        previous_head_sha256=replay._genesis_head(namespace),
        approval_id="hap_" + "a" * 64,
        subject={"case": "r25-unit"},
        nonce="1" * 64,
        digest_sha256="2" * 64,
    )


def _store(path: Path):
    return witness_service.Store(
        path,
        pause_namespace=None,
        pause_generation=None,
        pause_marker=None,
        release_marker=None,
        pause_timeout=0.1,
    )


def test_qualification_witness_persists_and_reloads_fsynced_chain(tmp_path):
    namespace = "r25-witness-persist"
    path = tmp_path / "witness.jsonl"
    record = _record(namespace)
    store = _store(path)

    ok, observed = store.append(
        namespace=namespace,
        expected_generation=0,
        expected_head_sha256=replay._genesis_head(namespace),
        record=record,
    )
    assert ok is True
    assert observed == record
    assert path.read_bytes().endswith(b"\n")

    reloaded = _store(path)
    assert reloaded.current_state(namespace) == replay._state(
        namespace, 1, record["head_sha256"]
    )
    assert reloaded.records_after(namespace, 0) == [record]


def test_qualification_witness_cas_conflict_does_not_append(tmp_path):
    namespace = "r25-witness-cas"
    path = tmp_path / "witness.jsonl"
    record = _record(namespace)
    store = _store(path)
    ok, _ = store.append(
        namespace=namespace,
        expected_generation=0,
        expected_head_sha256=replay._genesis_head(namespace),
        record=record,
    )
    assert ok is True
    before = path.read_bytes()

    ok, current = store.append(
        namespace=namespace,
        expected_generation=0,
        expected_head_sha256=replay._genesis_head(namespace),
        record=record,
    )
    assert ok is False
    assert current["generation"] == 1
    assert path.read_bytes() == before


def test_qualification_claim_identity_is_deterministic_and_scoped():
    one = qualification._claim_values("same")
    two = qualification._claim_values("same")
    other = qualification._claim_values("other")

    assert one == two
    assert one != other
    approval_id, subject, nonce, digest = one
    assert approval_id.startswith("hap_")
    assert len(approval_id) == 68
    assert len(nonce) == 64
    assert len(digest) == 64
    assert subject["qualification_case"] == "same"


def test_qualification_receipt_contract_cannot_claim_physical_multi_host():
    source = (
        ROOT / "tools" / "r25_replay_qualification.py"
    ).read_text(encoding="utf-8")
    assert '"production_qualified_multi_host": False' in source
    assert '"same_physical_host": True' in source
    assert '"worker_subprocess_domains": worker_count' in source
    assert '"qualification_harness_sha256": harness_sha256' in source
    assert '"witness_fixture_sha256": witness_fixture_sha256' in source
    assert '"merge": False' in source
    assert '"deploy": False' in source
    assert '"can_trade": False' in source
    assert '"capital_permission": "DENY"' in source


def test_qualification_witness_health_declares_not_production_ready():
    source = (
        ROOT / "tools" / "r25_witness_service.py"
    ).read_text(encoding="utf-8")
    assert '"production_ready": False' in source
    assert 'durability": "jsonl_fsync"' in source
