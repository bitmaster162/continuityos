from __future__ import annotations

import copy
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

import continuityos.witnessed_approval_replay as replay
from continuityos.multi_host_approval_replay import (
    ALREADY_CONSUMED, CLAIMED, MultiHostApprovalReplayError,
)

NS = "human-approval"
APPROVAL_ID = "hap_" + "a" * 64
NONCE = "1" * 64
DIGEST = "2" * 64
SUBJECT = {
    "repository": "bitmaster162/continuityos",
    "baseline_sha": "b" * 40,
    "candidate_sha": "c" * 40,
    "candidate_tree_sha": "d" * 40,
}


class RetryableTransactionError(RuntimeError):
    sqlstate = "40001"


class DeadlockTransactionError(RuntimeError):
    sqlstate = "40P01"


class DbState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.meta: dict[str, str] = {}
        self.claims: dict[tuple[str, str], tuple[str, str, str, str]] = {}
        self.states: dict[str, tuple[int, str]] = {}
        self.journal: dict[tuple[str, int], tuple[str, str, str, str, str, str, str]] = {}
        self.fail_next_commit = False
        self.retryable_commit_failures = 0
        self.active_transactions = 0


class FakeConnection:
    def __init__(self, state: DbState) -> None:
        self.state = state
        self.locked = False
        self.meta = {}
        self.claims = {}
        self.states = {}
        self.journal = {}

    def cursor(self):
        if not self.locked:
            self.state.lock.acquire()
            self.locked = True
            self.state.active_transactions += 1
            self.meta = copy.deepcopy(self.state.meta)
            self.claims = copy.deepcopy(self.state.claims)
            self.states = copy.deepcopy(self.state.states)
            self.journal = copy.deepcopy(self.state.journal)
        return FakeCursor(self)

    def commit(self) -> None:
        if self.state.retryable_commit_failures > 0:
            self.state.retryable_commit_failures -= 1
            self._release()
            raise RetryableTransactionError("simulated serialization failure")
        if self.state.fail_next_commit:
            self.state.fail_next_commit = False
            self._release()
            raise RuntimeError("simulated crash before database commit")
        self.state.meta = copy.deepcopy(self.meta)
        self.state.claims = copy.deepcopy(self.claims)
        self.state.states = copy.deepcopy(self.states)
        self.state.journal = copy.deepcopy(self.journal)
        self._release()

    def rollback(self) -> None:
        self._release()

    def close(self) -> None:
        self._release()

    def _release(self) -> None:
        if self.locked:
            self.locked = False
            self.state.active_transactions -= 1
            self.state.lock.release()


class FakeCursor:
    def __init__(self, con: FakeConnection) -> None:
        self.con = con
        self.rows: list[tuple] = []

    def execute(self, sql: str, params=None) -> None:
        q = " ".join(sql.lower().split())
        p = tuple(params or ())
        self.rows = []
        if q.startswith("set transaction isolation level"):
            return
        if q.startswith("create table"):
            return
        if q.startswith("insert into continuityos_replay_meta"):
            key = "witness_schema" if "witness_schema" in q else "schema"
            self.con.meta.setdefault(key, p[0])
            return
        if q.startswith("select value from continuityos_replay_meta"):
            key = "witness_schema" if "witness_schema" in q else "schema"
            if key in self.con.meta:
                self.rows = [(self.con.meta[key],)]
            return
        if q.startswith("select generation, head_sha256 from continuityos_replay_witness_state"):
            row = self.con.states.get(p[0])
            self.rows = [] if row is None else [row]
            return
        if q.startswith("select count(*) from continuityos_approval_claims"):
            self.rows = [(sum(1 for ns, _ in self.con.claims if ns == p[0]),)]
            return
        if q.startswith("insert into continuityos_replay_witness_state"):
            self.con.states[p[0]] = (p[1], p[2])
            return
        if q.startswith("select generation, previous_head_sha256"):
            ns = p[0]
            items = sorted(
                ((gen, row) for (row_ns, gen), row in self.con.journal.items() if row_ns == ns),
                key=lambda item: item[0],
            )
            self.rows = [(gen, *row) for gen, row in items]
            return
        if q.startswith("select approval_id, subject_json"):
            ns = p[0]
            items = sorted(
                ((aid, row) for (row_ns, aid), row in self.con.claims.items() if row_ns == ns),
                key=lambda item: item[0],
            )
            self.rows = [(aid, *row) for aid, row in items]
            return
        if q.startswith("insert into continuityos_approval_claims"):
            key = (p[0], p[1])
            row = (p[2], p[3], p[4], p[5])
            if key not in self.con.claims:
                self.con.claims[key] = row
                self.rows = [row]
            return
        if q.startswith("select subject_json"):
            row = self.con.claims.get((p[0], p[1]))
            self.rows = [] if row is None else [row]
            return
        if q.startswith("insert into continuityos_replay_witness_journal"):
            key = (p[0], p[1])
            row = (p[2], p[3], p[4], p[5], p[6], p[7], p[8])
            if key not in self.con.journal:
                self.con.journal[key] = row
                self.rows = [row]
            return
        if q.startswith("select previous_head_sha256"):
            row = self.con.journal.get((p[0], p[1]))
            self.rows = [] if row is None else [row]
            return
        if q.startswith("update continuityos_replay_witness_state"):
            new_generation, new_head, ns, expected_generation, expected_head = p
            if self.con.states.get(ns) == (expected_generation, expected_head):
                self.con.states[ns] = (new_generation, new_head)
                self.rows = [(new_generation, new_head)]
            return
        raise AssertionError(f"unexpected SQL: {q}")

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        rows = list(self.rows)
        self.rows = []
        return rows

    def close(self) -> None:
        pass


def connect_factory(state: DbState):
    return lambda dsn: FakeConnection(state)


class FakeWitness:
    witness_scope = replay.WITNESS_SCOPE

    def __init__(self, db: DbState | None = None) -> None:
        self.lock = threading.RLock()
        self.records: dict[str, list[dict]] = {}
        self.db = db
        self.fail_db_commit_after_append = False
        self.require_no_db_transaction = False

    def current_state(self, namespace: str) -> dict:
        if self.require_no_db_transaction and self.db is not None:
            assert self.db.active_transactions == 0
        with self.lock:
            records = self.records.get(namespace, [])
            if not records:
                return replay._state(namespace, 0, replay._genesis_head(namespace))
            last = records[-1]
            return replay._state(namespace, last["generation"], last["head_sha256"])

    def records_after(self, namespace: str, generation: int) -> list[dict]:
        if self.require_no_db_transaction and self.db is not None:
            assert self.db.active_transactions == 0
        with self.lock:
            return copy.deepcopy(self.records.get(namespace, [])[generation:])

    def append_record(
        self, namespace: str, expected_generation: int,
        expected_head_sha256: str, record: dict,
    ) -> dict:
        if self.require_no_db_transaction and self.db is not None:
            assert self.db.active_transactions == 0
        with self.lock:
            current = self.current_state(namespace)
            if (
                current["generation"] != expected_generation
                or current["head_sha256"] != expected_head_sha256
            ):
                raise RuntimeError("witness CAS conflict")
            expected = replay._require_record(
                record,
                namespace=namespace,
                expected_generation=expected_generation + 1,
                expected_previous_head=expected_head_sha256,
            )
            self.records.setdefault(namespace, []).append(copy.deepcopy(expected))
            if self.fail_db_commit_after_append:
                self.fail_db_commit_after_append = False
                assert self.db is not None
                self.db.fail_next_commit = True
            return copy.deepcopy(expected)


def authority(db: DbState, witness: FakeWitness):
    return replay.PostgresWitnessedApprovalReplayAuthority(
        "postgresql://r24-test",
        witness=witness,
        namespace=NS,
        connect=connect_factory(db),
    )


def claim(
    value: replay.PostgresWitnessedApprovalReplayAuthority,
    *,
    approval_id: str = APPROVAL_ID,
    subject: dict | None = None,
):
    return value.claim_once(
        approval_id=approval_id,
        subject=dict(subject or SUBJECT),
        nonce=NONCE,
        digest_sha256=DIGEST,
    )


def test_claim_once_and_replay_are_r23_receipt_compatible():
    db = DbState()
    witness = FakeWitness(db)
    first = authority(db, witness)
    one = claim(first)
    two = claim(authority(db, witness))
    assert one["status"] == CLAIMED
    assert two["status"] == ALREADY_CONSUMED
    assert one["schema"] == "continuityos.multi_host_replay_claim/v1"
    assert db.states[NS][0] == 1
    assert len(witness.records[NS]) == 1


def test_concurrent_authorities_append_exactly_one_witness_record():
    db = DbState()
    witness = FakeWitness(db)
    first = authority(db, witness)
    second = authority(db, witness)

    def run(index: int):
        return claim(first if index % 2 == 0 else second)

    with ThreadPoolExecutor(max_workers=12) as pool:
        receipts = list(pool.map(run, range(24)))
    statuses = [item["status"] for item in receipts]
    assert statuses.count(CLAIMED) == 1
    assert statuses.count(ALREADY_CONSUMED) == 23
    assert len(witness.records[NS]) == 1


def test_database_snapshot_rollback_recovers_from_witness():
    db = DbState()
    witness = FakeWitness(db)
    assert claim(authority(db, witness))["status"] == CLAIMED
    with db.lock:
        db.claims.clear()
        db.journal.clear()
        db.states[NS] = (0, replay._genesis_head(NS))
    recovered = authority(db, witness)
    assert db.states[NS][0] == 1
    assert claim(recovered)["status"] == ALREADY_CONSUMED


def test_crash_after_witness_append_before_db_commit_recovers():
    db = DbState()
    witness = FakeWitness(db)
    guard = authority(db, witness)
    witness.fail_db_commit_after_append = True
    with pytest.raises(MultiHostApprovalReplayError, match="database snapshot failed|synchronization failed|claim failed"):
        claim(guard)
    assert witness.current_state(NS)["generation"] == 1
    assert db.states[NS][0] == 0
    recovered = authority(db, witness)
    assert db.states[NS][0] == 1
    assert claim(recovered)["status"] == ALREADY_CONSUMED


def test_claim_row_tamper_fails_closed():
    db = DbState()
    witness = FakeWitness(db)
    assert claim(authority(db, witness))["status"] == CLAIMED
    with db.lock:
        old = db.claims[(NS, APPROVAL_ID)]
        db.claims[(NS, APPROVAL_ID)] = (old[0], old[1], old[2], "f" * 64)
    with pytest.raises(MultiHostApprovalReplayError, match="claim set tampered"):
        authority(db, witness)


def test_direct_unwitnessed_claim_fails_closed():
    db = DbState()
    witness = FakeWitness(db)
    authority(db, witness)
    subject_json = replay._canonical_json(SUBJECT)
    with db.lock:
        db.claims[(NS, APPROVAL_ID)] = (
            subject_json, replay._sha256_text(subject_json), NONCE, DIGEST
        )
    with pytest.raises(MultiHostApprovalReplayError, match="claim set tampered"):
        authority(db, witness)


def test_database_ahead_of_witness_fails_closed():
    db = DbState()
    witness = FakeWitness(db)
    assert claim(authority(db, witness))["status"] == CLAIMED
    with witness.lock:
        witness.records[NS] = []
    with pytest.raises(MultiHostApprovalReplayError, match="database ahead of witness"):
        authority(db, witness)


def test_witness_record_tamper_fails_closed_during_recovery():
    db = DbState()
    witness = FakeWitness(db)
    assert claim(authority(db, witness))["status"] == CLAIMED
    with db.lock:
        db.claims.clear()
        db.journal.clear()
        db.states[NS] = (0, replay._genesis_head(NS))
    with witness.lock:
        witness.records[NS][0]["digest_sha256"] = "e" * 64
    with pytest.raises(MultiHostApprovalReplayError, match="witness record tampered"):
        authority(db, witness)


def test_existing_r23_claims_require_explicit_migration():
    db = DbState()
    witness = FakeWitness(db)
    subject_json = replay._canonical_json(SUBJECT)
    db.claims[(NS, APPROVAL_ID)] = (
        subject_json, replay._sha256_text(subject_json), NONCE, DIGEST
    )
    with pytest.raises(MultiHostApprovalReplayError, match="explicit R23 migration required"):
        authority(db, witness)


def test_witness_contract_is_mandatory():
    class BadWitness:
        pass

    db = DbState()
    with pytest.raises(
        MultiHostApprovalReplayError, match="external append-only witness required"
    ):
        replay.PostgresWitnessedApprovalReplayAuthority(
            "postgresql://r24-test", witness=BadWitness(),
            namespace=NS, connect=connect_factory(db),
        )


def test_module_has_no_executor_or_authority_widening_surface():
    from pathlib import Path

    source = Path(replay.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "merge_pull_request" not in source
    assert "can_trade" not in source
    assert "capital_permission" not in source


def test_production_builder_requires_witnessed_markers(monkeypatch):
    import continuityos.trusted_human_approval_production as production

    class Stub:
        replay_scope = replay.MULTI_HOST
        rollback_protection = replay.ROLLBACK_PROTECTION

    marker = Stub()
    monkeypatch.setattr(
        production, "PostgresWitnessedApprovalReplayAuthority",
        lambda dsn, witness, namespace: marker,
    )
    assert production.build_witnessed_multi_host_production_replay_authority(
        replay_dsn="postgresql://shared",
        replay_witness=object(),
        replay_namespace=NS,
    ) is marker


def test_witnessed_production_binding_requires_multi_host_topology(monkeypatch):
    import continuityos.trusted_human_approval_production as production

    monkeypatch.setattr(
        production,
        "build_witnessed_multi_host_production_replay_authority",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("must not build")),
    )
    with pytest.raises(ValueError, match="requires topology > 1"):
        production.verify_and_consume_human_approval_production_multi_host_witnessed(
            replay_dsn="postgresql://shared", replay_witness=object(),
            replay_namespace=NS, execution_host_count=1,
            request_receipt={}, approval_envelope={}, trusted_key_registry={},
            pinned_registry_sha256="0" * 64, repository="bitmaster162/continuityos",
            current_base_sha="b" * 40, current_head_sha="c" * 40,
            current_tree_sha="d" * 40, now_unix=1,
        )


def test_witnessed_production_binding_passes_exact_authority(monkeypatch):
    import continuityos.trusted_human_approval_production as production

    marker = object()
    monkeypatch.setattr(
        production,
        "build_witnessed_multi_host_production_replay_authority",
        lambda **kwargs: marker,
    )
    monkeypatch.setattr(
        production, "verify_and_consume_human_approval",
        lambda **kwargs: kwargs["replay_guard"],
    )
    result = production.verify_and_consume_human_approval_production_multi_host_witnessed(
        replay_dsn="postgresql://shared", replay_witness=object(),
        replay_namespace=NS, execution_host_count=2,
        request_receipt={}, approval_envelope={}, trusted_key_registry={},
        pinned_registry_sha256="0" * 64, repository="bitmaster162/continuityos",
        current_base_sha="b" * 40, current_head_sha="c" * 40,
        current_tree_sha="d" * 40, now_unix=1,
    )
    assert result is marker


def test_live_r23_schema_meta_tamper_fails_closed():
    db = DbState()
    witness = FakeWitness(db)
    guard = authority(db, witness)
    with db.lock:
        db.meta["schema"] = "wrong-schema"
    with pytest.raises(MultiHostApprovalReplayError, match="R23 schema identity mismatch"):
        guard.synchronize()


def test_live_r24_schema_meta_tamper_fails_closed():
    db = DbState()
    witness = FakeWitness(db)
    guard = authority(db, witness)
    with db.lock:
        db.meta["witness_schema"] = "wrong-schema"
    with pytest.raises(MultiHostApprovalReplayError, match="R24 schema identity mismatch"):
        guard.synchronize()


def test_r17_replay_stays_denied_after_database_rollback_recovery():
    import importlib.util
    from pathlib import Path
    from continuityos.trusted_human_approval import verify_and_consume_human_approval

    fixture_path = Path(__file__).with_name("test_trusted_human_approval.py")
    spec = importlib.util.spec_from_file_location("_r17_fixture_r24", fixture_path)
    fixture = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(fixture)

    request = fixture.request()
    private, registry, pin = fixture.key_material()
    envelope = fixture.signed_envelope(request, private)
    db = DbState()
    witness = FakeWitness(db)
    result = verify_and_consume_human_approval(
        request_receipt=request,
        approval_envelope=envelope,
        trusted_key_registry=registry,
        pinned_registry_sha256=pin,
        repository=fixture.REPOSITORY,
        current_base_sha=fixture.BASE,
        current_head_sha=fixture.HEAD,
        current_tree_sha=fixture.TREE,
        now_unix=fixture.NOW,
        replay_guard=authority(db, witness),
    )
    assert result.replay_claim_receipt["status"] == CLAIMED

    with db.lock:
        db.claims.clear()
        db.journal.clear()
        db.states[NS] = (0, replay._genesis_head(NS))

    recovered = authority(db, witness)
    with pytest.raises(ValueError, match="approval replay detected"):
        verify_and_consume_human_approval(
            request_receipt=request,
            approval_envelope=envelope,
            trusted_key_registry=registry,
            pinned_registry_sha256=pin,
            repository=fixture.REPOSITORY,
            current_base_sha=fixture.BASE,
            current_head_sha=fixture.HEAD,
            current_tree_sha=fixture.TREE,
            now_unix=fixture.NOW,
            replay_guard=recovered,
        )



def test_external_witness_io_occurs_outside_database_transaction():
    db = DbState()
    witness = FakeWitness(db)
    witness.require_no_db_transaction = True
    guard = authority(db, witness)
    assert claim(guard)["status"] == CLAIMED
    assert claim(guard)["status"] == ALREADY_CONSUMED


def _claim_id(ch: str) -> str:
    return "hap_" + ch * 64


def test_truncated_witness_history_fails_closed():
    db = DbState()
    witness = FakeWitness(db)
    guard = authority(db, witness)
    assert claim(guard, approval_id=_claim_id("a"))["status"] == CLAIMED
    assert claim(guard, approval_id=_claim_id("b"))["status"] == CLAIMED
    with db.lock:
        db.claims.clear()
        db.journal.clear()
        db.states[NS] = (0, replay._genesis_head(NS))
    original = witness.records_after
    witness.records_after = lambda namespace, generation: original(
        namespace, generation
    )[:1]
    with pytest.raises(
        MultiHostApprovalReplayError, match="witness history incomplete"
    ):
        authority(db, witness)


def test_reordered_witness_history_fails_closed():
    db = DbState()
    witness = FakeWitness(db)
    guard = authority(db, witness)
    assert claim(guard, approval_id=_claim_id("a"))["status"] == CLAIMED
    assert claim(guard, approval_id=_claim_id("b"))["status"] == CLAIMED
    with db.lock:
        db.claims.clear()
        db.journal.clear()
        db.states[NS] = (0, replay._genesis_head(NS))
    original = witness.records_after
    witness.records_after = lambda namespace, generation: list(
        reversed(original(namespace, generation))
    )
    with pytest.raises(
        MultiHostApprovalReplayError, match="witness generation gap"
    ):
        authority(db, witness)


def test_ambiguous_append_response_never_promotes_to_claimed():
    class AmbiguousWitness(FakeWitness):
        def __init__(self, db):
            super().__init__(db)
            self.once = True

        def append_record(self, *args, **kwargs):
            value = super().append_record(*args, **kwargs)
            if self.once:
                self.once = False
                raise RuntimeError("response lost after durable append")
            return value

    db = DbState()
    witness = AmbiguousWitness(db)
    receipt = claim(authority(db, witness))
    assert receipt["status"] == ALREADY_CONSUMED
    assert len(witness.records[NS]) == 1
    assert db.states[NS][0] == 1


def test_mixed_synchronize_and_claim_concurrency_is_consistent():
    db = DbState()
    witness = FakeWitness(db)
    first = authority(db, witness)
    second = authority(db, witness)

    def run(index: int):
        if index % 3 == 0:
            return ("sync", (first if index % 2 == 0 else second).synchronize())
        return ("claim", claim(first if index % 2 == 0 else second))

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(run, range(30)))
    receipts = [value for kind, value in results if kind == "claim"]
    statuses = [item["status"] for item in receipts]
    assert statuses.count(CLAIMED) == 1
    assert statuses.count(ALREADY_CONSUMED) == len(receipts) - 1
    assert witness.current_state(NS)["generation"] == 1
    assert db.states[NS][0] == 1


def test_namespaces_are_isolated():
    db = DbState()
    witness = FakeWitness(db)
    left = replay.PostgresWitnessedApprovalReplayAuthority(
        "postgresql://r24-test", witness=witness, namespace="human-approval-a",
        connect=connect_factory(db),
    )
    right = replay.PostgresWitnessedApprovalReplayAuthority(
        "postgresql://r24-test", witness=witness, namespace="human-approval-b",
        connect=connect_factory(db),
    )
    assert claim(left)["status"] == CLAIMED
    assert claim(right)["status"] == CLAIMED
    assert witness.current_state("human-approval-a")["generation"] == 1
    assert witness.current_state("human-approval-b")["generation"] == 1


def test_retryable_transaction_error_detection_is_sqlstate_scoped():
    assert replay._is_retryable_transaction_error(
        RetryableTransactionError("serialization")
    )
    assert replay._is_retryable_transaction_error(
        DeadlockTransactionError("deadlock")
    )
    outer = RuntimeError("wrapper")
    outer.__cause__ = RetryableTransactionError("nested serialization")
    assert replay._is_retryable_transaction_error(outer)
    contextual = RuntimeError("ordinary wrapper")
    contextual.__context__ = RetryableTransactionError("implicit serialization context")
    assert not replay._is_retryable_transaction_error(contextual)
    assert not replay._is_retryable_transaction_error(
        RuntimeError("ordinary failure")
    )


def test_snapshot_retry_budget_counts_failures_not_successful_calls():
    db = DbState()
    witness = FakeWitness(db)
    guard = authority(db, witness)
    budget = replay._RetryBudget(2)

    for _ in range(replay._LOGICAL_CONTENTION_LIMIT + 1):
        state = guard._snapshot_database(retry_budget=budget)
        assert state["generation"] == 0
    assert budget.remaining == 2

    db.retryable_commit_failures = 1
    state = guard._snapshot_database(retry_budget=budget)
    assert state["generation"] == 0
    assert budget.remaining == 1

    db.retryable_commit_failures = 2
    with pytest.raises(MultiHostApprovalReplayError, match="database snapshot contention"):
        guard._snapshot_database(retry_budget=budget)
    assert budget.remaining == 0


def test_snapshot_retries_retryable_serialization_failure():
    db = DbState()
    witness = FakeWitness(db)
    guard = authority(db, witness)
    db.retryable_commit_failures = 1
    state = guard.synchronize()
    assert state["generation"] == 0
    assert db.retryable_commit_failures == 0
