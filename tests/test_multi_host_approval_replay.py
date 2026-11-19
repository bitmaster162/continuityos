from __future__ import annotations

import hashlib
import importlib.util
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import continuityos.multi_host_approval_replay as replay
import continuityos.trusted_human_approval_production as production
from continuityos.trusted_human_approval import verify_and_consume_human_approval


APPROVAL_ID = "hap_" + "a" * 64
NONCE = "1" * 64
DIGEST = "2" * 64
SUBJECT = {
    "repository": "bitmaster162/continuityos",
    "baseline_sha": "b" * 40,
    "candidate_sha": "c" * 40,
    "candidate_tree_sha": "d" * 40,
}


class SharedState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.schema: str | None = None
        self.claims: dict[tuple[str, str], tuple[str, str, str, str]] = {}


class FakeCursor:
    def __init__(self, state: SharedState) -> None:
        self.state = state
        self.rows: list[tuple] = []

    def execute(self, sql: str, params=None) -> None:
        query = " ".join(sql.lower().split())
        params = tuple(params or ())
        if query.startswith("set transaction isolation level"):
            self.rows = []
        elif query.startswith("create table"):
            self.rows = []
        elif query.startswith("insert into continuityos_replay_meta"):
            with self.state.lock:
                if self.state.schema is None:
                    self.state.schema = params[0]
            self.rows = []
        elif query.startswith("select value from continuityos_replay_meta"):
            self.rows = [] if self.state.schema is None else [(self.state.schema,)]
        elif query.startswith("insert into continuityos_approval_claims"):
            key = (params[0], params[1])
            row = (params[2], params[3], params[4], params[5])
            with self.state.lock:
                if key not in self.state.claims:
                    self.state.claims[key] = row
                    self.rows = [row]
                else:
                    self.rows = []
        elif query.startswith("select subject_json"):
            key = (params[0], params[1])
            with self.state.lock:
                row = self.state.claims.get(key)
            self.rows = [] if row is None else [row]
        else:
            raise AssertionError(f"unexpected SQL: {query}")

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def close(self) -> None:
        pass


class FakeConnection:
    def __init__(self, state: SharedState) -> None:
        self.state = state

    def cursor(self) -> FakeCursor:
        return FakeCursor(self.state)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass


def fake_factory(state: SharedState):
    return lambda dsn: FakeConnection(state)


def authority(state: SharedState) -> replay.PostgresApprovalReplayAuthority:
    return replay.PostgresApprovalReplayAuthority(
        "postgresql://r23-test",
        namespace="human-approval",
        connect=fake_factory(state),
    )


def claim(value: replay.PostgresApprovalReplayAuthority, subject=None):
    return value.claim_once(
        approval_id=APPROVAL_ID,
        subject=dict(subject or SUBJECT),
        nonce=NONCE,
        digest_sha256=DIGEST,
    )


def test_two_authorities_allow_exactly_one_claim():
    state = SharedState()
    first = authority(state)
    second = authority(state)

    def run(index: int):
        return claim(first if index % 2 == 0 else second)

    with ThreadPoolExecutor(max_workers=16) as pool:
        receipts = list(pool.map(run, range(32)))

    statuses = [item["status"] for item in receipts]
    assert statuses.count(replay.CLAIMED) == 1
    assert statuses.count(replay.ALREADY_CONSUMED) == 31
    assert all(item["replay_scope"] == replay.MULTI_HOST for item in receipts)
    assert len({item["subject_sha256"] for item in receipts}) == 1


def test_same_approval_id_with_different_binding_is_conflict():
    state = SharedState()
    guard = authority(state)
    assert claim(guard)["status"] == replay.CLAIMED
    changed = dict(SUBJECT)
    changed["candidate_tree_sha"] = "e" * 40
    receipt = claim(authority(state), changed)
    assert receipt["status"] == replay.CONFLICT
    assert receipt["subject_sha256"] != receipt["existing_subject_sha256"]


def test_missing_psycopg_fails_closed_without_fallback(monkeypatch):
    def missing(name: str):
        assert name == "psycopg"
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(replay.importlib, "import_module", missing)
    with pytest.raises(
        replay.MultiHostApprovalReplayError, match="psycopg backend unavailable"
    ):
        replay.PostgresApprovalReplayAuthority("postgresql://missing")


def load_r17_fixture():
    path = Path(__file__).with_name("test_trusted_human_approval.py")
    spec = importlib.util.spec_from_file_location("_r17_fixture_r23", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


R17 = load_r17_fixture()


class RecordingAuthority:
    replay_scope = replay.MULTI_HOST

    def __init__(self, status: str = replay.CLAIMED) -> None:
        self.status = status
        self.calls: list[dict] = []

    def claim_once(self, **kwargs):
        self.calls.append(dict(kwargs))
        value = {
            "schema": replay.CLAIM_SCHEMA,
            "replay_scope": replay.MULTI_HOST,
            "backend": "TEST_SHARED_CAS",
            "namespace": "human-approval",
            "approval_id": kwargs["approval_id"],
            "subject": dict(kwargs["subject"]),
            "subject_sha256": hashlib.sha256(
                json.dumps(kwargs["subject"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            ).hexdigest(),
            "nonce": kwargs["nonce"],
            "digest_sha256": kwargs["digest_sha256"],
            "status": self.status,
        }
        value["receipt_id"] = "mrc_" + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()
        return value


def valid_r17_inputs():
    request = R17.request()
    private, registry, pin = R17.key_material()
    envelope = R17.signed_envelope(request, private)
    return request, envelope, registry, pin


def verify_with(authority_value):
    request, envelope, registry, pin = valid_r17_inputs()
    result = verify_and_consume_human_approval(
        request_receipt=request,
        approval_envelope=envelope,
        trusted_key_registry=registry,
        pinned_registry_sha256=pin,
        repository=R17.REPOSITORY,
        current_base_sha=R17.BASE,
        current_head_sha=R17.HEAD,
        current_tree_sha=R17.TREE,
        now_unix=R17.NOW,
        replay_guard=authority_value,
    )
    return request, envelope, result


def test_r17_binds_rich_multi_host_claim_to_exact_subject_and_digest():
    authority_value = RecordingAuthority()
    request, envelope, result = verify_with(authority_value)
    assert result.replay_claim_receipt is not None
    assert result.replay_claim_receipt["status"] == replay.CLAIMED
    assert len(authority_value.calls) == 1
    call = authority_value.calls[0]
    assert call["approval_id"] == result.approval_id
    assert call["nonce"] == envelope["approval_nonce"]
    assert call["subject"] == {
        "request_receipt_id": request["receipt_id"],
        "repository": request["repository"],
        "baseline_sha": request["baseline_sha"],
        "candidate_sha": request["candidate_sha"],
        "candidate_tree_sha": request["candidate_tree_sha"],
    }
    expected = hashlib.sha256(
        json.dumps(
            envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()
    assert call["digest_sha256"] == expected


def test_r17_rejects_already_consumed_and_conflicting_claims():
    with pytest.raises(ValueError, match="approval replay detected"):
        verify_with(RecordingAuthority(replay.ALREADY_CONSUMED))
    with pytest.raises(ValueError, match="replay binding conflict"):
        verify_with(RecordingAuthority(replay.CONFLICT))


def test_single_host_production_binding_rejects_multi_host_topology(tmp_path: Path):
    with pytest.raises(ValueError, match="MULTI_HOST replay required"):
        production.verify_and_consume_human_approval_production(
            replay_db_path=tmp_path / "single.sqlite3",
            request_receipt={}, approval_envelope={}, trusted_key_registry={},
            pinned_registry_sha256="0" * 64,
            repository="bitmaster162/continuityos",
            current_base_sha="b" * 40,
            current_head_sha="c" * 40,
            current_tree_sha="d" * 40,
            now_unix=1,
            execution_host_count=2,
        )


def test_multi_host_production_binding_has_no_sqlite_fallback(monkeypatch):
    marker = RecordingAuthority()
    monkeypatch.setattr(
        production,
        "build_multi_host_production_replay_authority",
        lambda **kwargs: marker,
    )
    monkeypatch.setattr(
        production,
        "verify_and_consume_human_approval",
        lambda **kwargs: kwargs["replay_guard"],
    )
    result = production.verify_and_consume_human_approval_production_multi_host(
        replay_dsn="postgresql://shared",
        replay_namespace="human-approval",
        execution_host_count=2,
        request_receipt={}, approval_envelope={}, trusted_key_registry={},
        pinned_registry_sha256="0" * 64,
        repository="bitmaster162/continuityos",
        current_base_sha="b" * 40,
        current_head_sha="c" * 40,
        current_tree_sha="d" * 40,
        now_unix=1,
    )
    assert result is marker
    assert marker.replay_scope == replay.MULTI_HOST


def test_multi_host_production_binding_requires_multi_host_topology(monkeypatch):
    monkeypatch.setattr(
        production,
        "build_multi_host_production_replay_authority",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("must not build")),
    )
    with pytest.raises(ValueError, match="topology > 1"):
        production.verify_and_consume_human_approval_production_multi_host(
            replay_dsn="postgresql://shared", replay_namespace="human-approval",
            execution_host_count=1, request_receipt={}, approval_envelope={},
            trusted_key_registry={}, pinned_registry_sha256="0" * 64,
            repository="bitmaster162/continuityos", current_base_sha="b" * 40,
            current_head_sha="c" * 40, current_tree_sha="d" * 40, now_unix=1,
        )


def test_schema_identity_drift_fails_closed():
    state = SharedState()
    state.schema = "wrong-schema"
    with pytest.raises(
        replay.MultiHostApprovalReplayError, match="schema identity mismatch"
    ):
        authority(state)



def test_live_schema_identity_drift_fails_closed():
    state = SharedState()
    guard = authority(state)
    state.schema = "wrong-schema"
    with pytest.raises(
        replay.MultiHostApprovalReplayError, match="schema identity mismatch"
    ):
        claim(guard)


def test_r17_rejects_tampered_rich_claim_receipt():
    class TamperedAuthority(RecordingAuthority):
        def claim_once(self, **kwargs):
            value = super().claim_once(**kwargs)
            value["subject_sha256"] = "0" * 64
            return value

    with pytest.raises(ValueError, match="replay claim receipt tampered|replay claim binding mismatch"):
        verify_with(TamperedAuthority())

def test_multi_host_module_has_no_merge_or_deploy_executor_surface():
    source = Path(replay.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "merge_pull_request" not in source
    assert "deployment" not in source.lower()
    assert "can_trade" not in source
    assert "capital_permission" not in source
    assert "ON CONFLICT (namespace, approval_id) DO NOTHING" in source
    assert "PRIMARY KEY(namespace, approval_id)" in source
