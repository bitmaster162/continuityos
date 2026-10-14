"""Offline-first MCP selection; optional backends are synthetic sentinels only."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from continuityos import current_effect_boundary, embedders, mcp_server
from continuityos.embed import HashingEmbedder
from continuityos.memory import Memory


PACKAGE_ROOT = Path(mcp_server.__file__).resolve().parents[1]
OFFLINE_MODES = [None, "", " ", "hash", "HASH", "hashing", " HASHING ",
                 "offline", " Offline ", "local", "LOCAL"]
FAST_MODES = ["fast", " FAST ", "fastembed", "FastEmbed"]


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    for key in tuple(os.environ):
        if key.startswith("CONTINUITYOS_CURRENT_"):
            monkeypatch.delenv(key)
    monkeypatch.delenv("CONTINUITYOS_EMBEDDER", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("CONTINUITYOS_SILENCE_EMBED_WARN", "1")

    def no_real_backend(*args, **kwargs):
        raise AssertionError("A test must never construct the real optional backend")

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", no_real_backend)


def set_mode(monkeypatch, mode):
    if mode is None:
        monkeypatch.delenv("CONTINUITYOS_EMBEDDER", raising=False)
    else:
        monkeypatch.setenv("CONTINUITYOS_EMBEDDER", mode)


@contextmanager
def opened_server(db, policy=""):
    server = mcp_server.Server(str(db), str(policy))
    try:
        yield server
    finally:
        server.m.store.con.close()


@pytest.mark.parametrize("mode", OFFLINE_MODES)
def test_offline_modes_never_construct_optional_backend(monkeypatch, tmp_path, mode):
    set_mode(monkeypatch, mode)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("constructed")
        raise AssertionError("No optional model in an offline mode")

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", forbidden)
    with opened_server(tmp_path / "memory.db") as server:
        assert isinstance(server.m.embed, HashingEmbedder)
        assert calls == []


@pytest.mark.parametrize("mode", FAST_MODES)
def test_fast_aliases_require_and_honor_explicit_opt_in(monkeypatch, tmp_path, mode):
    set_mode(monkeypatch, mode)
    instances = []

    class FakeFast:
        def __init__(self):
            instances.append(self)

        def __call__(self, text):
            return HashingEmbedder()(text)

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", FakeFast)
    with opened_server(tmp_path / "memory.db") as server:
        assert len(instances) == 1
        assert server.m.embed is instances[0]
        assert server.db_path == os.path.normcase(os.path.realpath(tmp_path / "memory.db"))


@pytest.mark.parametrize("failure", [ImportError, RuntimeError])
def test_explicit_fast_failure_is_closed_before_memory(monkeypatch, tmp_path, failure):
    # R2 deliberately replaces the R1 fallback contract following Claude review.
    set_mode(monkeypatch, "fast")
    calls = []

    def unavailable(*args, **kwargs):
        calls.append("constructor")
        raise failure("synthetic unavailable optional loader")

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", unavailable)
    with pytest.raises(RuntimeError, match="FAST_EMBEDDER_UNAVAILABLE"):
        with opened_server(tmp_path / "memory.db"):
            pass
    assert calls == ["constructor"]
    assert not (tmp_path / "memory.db").exists()


@pytest.mark.parametrize("mode", ["auto", "unknown", "0", "hash+fast", "fast\nhash", "fast embed"])
def test_unknown_mode_fails_before_resolution_memory_or_optional_loader(monkeypatch, tmp_path, mode):
    set_mode(monkeypatch, mode)
    touched = []

    def forbidden(*args, **kwargs):
        touched.append("resolution-or-loader-or-memory")
        raise AssertionError("Unknown mode reached an effectful dependency")

    monkeypatch.setattr(mcp_server, "resolve_memory_db", forbidden)
    monkeypatch.setattr(mcp_server, "Memory", forbidden)
    monkeypatch.setattr(embedders, "FastEmbedEmbedder", forbidden)
    with pytest.raises(ValueError, match="UNSUPPORTED_EMBEDDER_MODE"):
        mcp_server.Server(str(tmp_path / "must-not-exist.db"))
    assert touched == []
    assert not (tmp_path / "must-not-exist.db").exists()


def test_unknown_mode_does_not_touch_an_existing_database(monkeypatch, tmp_path):
    db = tmp_path / "existing.db"
    memory = Memory(str(db))
    memory.remember("synthetic sentinel", namespace="facts")
    memory.store.con.close()
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    set_mode(monkeypatch, "unsupported")
    try:
        with opened_server(db):
            pytest.fail("Unknown mode was accepted")
    except ValueError as exc:
        assert "UNSUPPORTED_EMBEDDER_MODE" in str(exc)
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    assert not Path(str(db) + "-wal").exists()


@pytest.mark.parametrize("mode", ["hash", "fast"])
def test_memory_initialization_failure_is_not_retried_with_another_embedder(monkeypatch, tmp_path, mode):
    set_mode(monkeypatch, mode)
    backend = object()
    memory_calls = []
    monkeypatch.setattr(embedders, "FastEmbedEmbedder", lambda: backend)

    def failed_memory(*args, **kwargs):
        memory_calls.append((args, kwargs))
        raise OSError("SYNTHETIC_MEMORY_OPEN_FAILED")

    monkeypatch.setattr(mcp_server, "Memory", failed_memory)
    with pytest.raises(OSError, match="SYNTHETIC_MEMORY_OPEN_FAILED"):
        mcp_server.Server(str(tmp_path / "unopened.db"))
    assert len(memory_calls) == 1
    assert not (tmp_path / "unopened.db").exists()


def test_mode_is_sampled_once_per_server_not_cached_globally(monkeypatch, tmp_path):
    fake = HashingEmbedder()
    calls = []

    def constructor():
        calls.append("fast")
        return fake

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", constructor)
    set_mode(monkeypatch, "hash")
    with opened_server(tmp_path / "one.db") as first:
        first_embedder = first.m.embed
        set_mode(monkeypatch, "fast")
        with opened_server(tmp_path / "two.db") as second:
            assert second.m.embed is fake
            assert first.m.embed is first_embedder and first_embedder is not fake
        set_mode(monkeypatch, "local")
        with opened_server(tmp_path / "three.db") as third:
            assert third.m.embed is not fake
    assert calls == ["fast"]


def test_existing_policy_snapshot_and_db_binding_are_preserved(monkeypatch, tmp_path):
    set_mode(monkeypatch, "hash")
    db = tmp_path / "existing.db"
    memory = Memory(str(db))
    memory.store.con.close()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"default_decision": "DENY"}), encoding="utf-8")
    with opened_server(db, policy) as server:
        broker = server._gate_broker()
        assert broker.db == server.db_path == os.path.normcase(os.path.realpath(db))
        assert broker._policy_snapshot is server.policy
        assert server.policy["default_decision"] == "DENY"
        policy.write_text(json.dumps({"default_decision": "ALLOW"}), encoding="utf-8")
        assert server.policy["default_decision"] == "DENY"


@pytest.mark.parametrize("mode", ["hash", "fast", "unknown"])
@pytest.mark.parametrize("surface", ["Server", "main"])
def test_declared_current_session_denies_before_embedder_or_db(monkeypatch, tmp_path, mode, surface):
    set_mode(monkeypatch, mode)
    monkeypatch.setenv("CONTINUITYOS_CURRENT_SESSION_REQUIRED", "1")
    touched = []

    def forbidden(*args, **kwargs):
        touched.append("effect")
        raise AssertionError("CURRENT must deny before resolution or loader")

    monkeypatch.setattr(mcp_server, "resolve_memory_db", forbidden)
    monkeypatch.setattr(mcp_server, "Memory", forbidden)
    monkeypatch.setattr(embedders, "FastEmbedEmbedder", forbidden)
    with pytest.raises(current_effect_boundary.CurrentEffectBoundaryError):
        if surface == "Server":
            mcp_server.Server(str(tmp_path / "unopened.db"))
        else:
            mcp_server.main()
    assert touched == []
    assert not (tmp_path / "unopened.db").exists()


def run_stdio_process(tmp_path, mode, *, required=False, loader_failure=False):
    stub = tmp_path / "optional-stub"
    stub.mkdir()
    imported = tmp_path / "optional-imported.txt"
    constructed = tmp_path / "optional-constructed.txt"
    (stub / "fastembed.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "Path(os.environ['COS_TEST_OPTIONAL_IMPORTED']).write_text('imported')\n"
        "class TextEmbedding:\n"
        " def __init__(self, **kwargs):\n"
        "  Path(os.environ['COS_TEST_OPTIONAL_CONSTRUCTED']).write_text('constructed')\n"
        " def embed(self, texts):\n"
        "  for text in texts: yield [1.0] + [0.0] * 383\n",
        encoding="utf-8",
    )
    if loader_failure:
        (stub / "fastembed.py").write_text(
            "raise ImportError('SYNTHETIC_FASTEMBED_IMPORT_FAILURE')\n", encoding="utf-8",
        )
    env = {k: v for k, v in os.environ.items() if k.upper() in {
        "SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT"
    }}
    home = tmp_path / "child-home"
    home.mkdir()
    env.update({
        "HOME": str(home), "USERPROFILE": str(home), "APPDATA": str(home),
        "LOCALAPPDATA": str(home), "TEMP": str(tmp_path), "TMP": str(tmp_path),
        "PYTHONPATH": str(stub) + os.pathsep + str(PACKAGE_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1", "CONTINUITYOS_SILENCE_EMBED_WARN": "1",
        "COS_TEST_OPTIONAL_IMPORTED": str(imported),
        "COS_TEST_OPTIONAL_CONSTRUCTED": str(constructed),
    })
    if mode is not None:
        env["CONTINUITYOS_EMBEDDER"] = mode
    if required:
        env["CONTINUITYOS_CURRENT_SESSION_REQUIRED"] = "1"
    db = tmp_path / "stdio.db"
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "remember", "arguments": {"text": "synthetic MCP offline marker"}}},
    ]
    process = subprocess.run(
        [sys.executable, "-B", "-m", "continuityos.mcp_server", "--db", str(db)],
        input="".join(json.dumps(r) + "\n" for r in requests),
        cwd=str(tmp_path), env=env, capture_output=True,
        text=True, encoding="utf-8", timeout=25,
    )
    return process, db, imported, constructed


@pytest.mark.parametrize("mode", [None, "hash", "local", "fast", "fastembed"])
def test_real_stdio_entrypoint_obeys_mode_without_real_model(tmp_path, mode):
    process, db, imported, constructed = run_stdio_process(tmp_path, mode)
    assert process.returncode == 0, process.stderr
    responses = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
    assert [r["id"] for r in responses] == [1, 2]
    assert not responses[1]["result"].get("isError")
    assert "stored #" in responses[1]["result"]["content"][0]["text"]
    assert db.exists()
    opted_in = mode in {"fast", "fastembed"}
    assert imported.exists() is opted_in
    assert constructed.exists() is opted_in


def test_real_stdio_invalid_mode_exits_before_protocol_and_database(tmp_path):
    process, db, imported, constructed = run_stdio_process(tmp_path, "unknown")
    assert process.returncode != 0
    assert "UNSUPPORTED_EMBEDDER_MODE" in process.stderr
    assert not process.stdout.strip()
    assert not db.exists() and not imported.exists() and not constructed.exists()


@pytest.mark.parametrize("mode", ["hash", "fast", "unknown"])
def test_real_stdio_current_boundary_precedes_mode_selection(tmp_path, mode):
    process, db, imported, constructed = run_stdio_process(tmp_path, mode, required=True)
    assert process.returncode != 0
    assert "CurrentEffectBoundaryError" in process.stderr
    assert not process.stdout.strip()
    assert not db.exists() and not imported.exists() and not constructed.exists()


# R2: guard a complete startup snapshot, not only one sampled vector row.
def seed_vector_dimensions(db, dimensions, *, separate_namespaces=False):
    memory = Memory(str(db))
    try:
        for index, dimension in enumerate(dimensions):
            memory.store.add(
                "synthetic compatibility record " + str(index),
                namespace=("space-" + str(index)) if separate_namespaces else "notes",
                vec=None if dimension is None else [1.0] + [0.0] * (dimension - 1),
            )
    finally:
        memory.store.con.close()


def read_vector_snapshot(db):
    import sqlite3
    connection = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
    try:
        return connection.execute(
            "SELECT id, namespace, text, meta, vec FROM items ORDER BY id"
        ).fetchall()
    finally:
        connection.close()


def track_created_memory(monkeypatch):
    created = []

    def memory_factory(*args, **kwargs):
        memory = Memory(*args, **kwargs)
        created.append(memory)
        return memory

    monkeypatch.setattr(mcp_server, "Memory", memory_factory)
    return created


def assert_memory_closed(created):
    import sqlite3
    assert len(created) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        created[0].store.con.execute("SELECT 1")


@pytest.mark.parametrize("mode", OFFLINE_MODES)
def test_existing_384_rejected_before_first_mcp_write(monkeypatch, tmp_path, mode):
    db = tmp_path / "legacy-fast.db"
    seed_vector_dimensions(db, [384])
    before = read_vector_snapshot(db)
    before_sha = hashlib.sha256(db.read_bytes()).hexdigest()
    created = track_created_memory(monkeypatch)
    set_mode(monkeypatch, mode)
    with pytest.raises(ValueError, match=r"EMBEDDER_DIMENSION_MISMATCH.*store=384.*selected=256"):
        with opened_server(db):
            pass
    assert_memory_closed(created)
    # The read-only snapshot observer can itself create WAL sidecars.
    assert not Path(str(db) + "-wal").exists()
    assert read_vector_snapshot(db) == before
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before_sha


@pytest.mark.parametrize("mode,dimension", [(None, 256), ("fast", 384)])
def test_compatible_backend_probed_once_without_record_content(monkeypatch, tmp_path, mode, dimension):
    db = tmp_path / "compatible.db"
    seed_vector_dimensions(db, [dimension, dimension])
    calls = []
    queries = []

    class RecordingBackend:
        def __call__(self, text):
            calls.append(text)
            return [1.0] + [0.0] * (dimension - 1)

    backend = RecordingBackend()
    if mode == "fast":
        monkeypatch.setattr(embedders, "FastEmbedEmbedder", lambda: backend)

    def memory_factory(*args, **kwargs):
        memory = Memory(*args, **kwargs)
        if mode is None:
            actual = memory.embed

            def recorded_hash(text):
                calls.append(text)
                return actual(text)

            memory.embed = recorded_hash
        memory.store.con.set_trace_callback(queries.append)
        return memory

    monkeypatch.setattr(mcp_server, "Memory", memory_factory)
    set_mode(monkeypatch, mode)
    with opened_server(db) as server:
        assert len(calls) == 1
        assert calls[0] == "continuityos:mcp-embedding-dimension-probe:v1"
        reads = [q for q in queries if q.lstrip().upper().startswith("SELECT")]
        assert len(reads) == 1
        assert "length(vec)" in reads[0].lower()
        assert "typeof(vec)" in reads[0].lower()
        assert " text" not in reads[0].lower()
        assert " namespace" not in reads[0].lower()
        assert "LIMIT 1" not in reads[0].upper()
        assert server.m.store.count() == 2
        server.call("remember", {"text": "synthetic compatible write"})
        result = json.loads(server.call("recall", {"query": "synthetic", "k": 10}))
        assert result
        assert server.m.store.count() == 3


@pytest.mark.parametrize("mode,dimensions", [
    ("hash", [256, 384]), ("hash", [384, 256]),
    ("fast", [384, 256]), ("fast", [256, 384]),
])
def test_all_namespaces_checked_not_one_sample(monkeypatch, tmp_path, mode, dimensions):
    db = tmp_path / "mixed.db"
    seed_vector_dimensions(db, dimensions, separate_namespaces=True)
    before = read_vector_snapshot(db)
    if mode == "fast":
        monkeypatch.setattr(embedders, "FastEmbedEmbedder", lambda: (lambda text: [1.0] + [0.0] * 383))
    set_mode(monkeypatch, mode)
    created = track_created_memory(monkeypatch)
    with pytest.raises(ValueError, match="EMBEDDER_DIMENSION_MISMATCH"):
        with opened_server(db):
            pass
    assert_memory_closed(created)
    assert read_vector_snapshot(db) == before


@pytest.mark.parametrize("bad_blob", [b"", b"x", b"x" * 1025, "not-a-vector", 42])
def test_invalid_stored_vector_shape_fails_closed(monkeypatch, tmp_path, bad_blob):
    import sqlite3
    db = tmp_path / "malformed.db"
    seed_vector_dimensions(db, [256])
    connection = sqlite3.connect(db)
    try:
        connection.execute("UPDATE items SET vec=?", (bad_blob,))
        connection.commit()
    finally:
        connection.close()
    before = read_vector_snapshot(db)
    created = track_created_memory(monkeypatch)
    with pytest.raises(ValueError, match="EMBEDDER_VECTOR_DATA_INVALID"):
        with opened_server(db):
            pass
    assert_memory_closed(created)
    assert read_vector_snapshot(db) == before


@pytest.mark.parametrize("dimensions", [[], [None], [None, 256]])
def test_empty_or_vectorless_store_uses_selected_backend_without_fabricated_constraint(tmp_path, dimensions):
    db = tmp_path / "vectorless.db"
    seed_vector_dimensions(db, dimensions)
    with opened_server(db) as server:
        server.call("remember", {"text": "synthetic first vector"})
        assert server.m.store.count() == len(dimensions) + 1
        assert json.loads(server.call("recall", {"query": "synthetic"}))


@pytest.mark.parametrize("bad_probe", [None, [], "not-a-vector", b"not-a-vector", True])
def test_invalid_probe_closes_connection_before_serving(monkeypatch, tmp_path, bad_probe):
    db = tmp_path / "probe-invalid.db"
    seed_vector_dimensions(db, [])
    set_mode(monkeypatch, "fast")
    monkeypatch.setattr(embedders, "FastEmbedEmbedder", lambda: (lambda text: bad_probe))
    created = track_created_memory(monkeypatch)
    with pytest.raises(ValueError, match="EMBEDDER_PROBE_INVALID"):
        with opened_server(db):
            pass
    assert_memory_closed(created)
    assert read_vector_snapshot(db) == []


def test_probe_exception_closes_connection_without_fallback(monkeypatch, tmp_path):
    db = tmp_path / "probe-error.db"
    seed_vector_dimensions(db, [384])
    before = read_vector_snapshot(db)
    calls = []

    def probe(text):
        calls.append(text)
        raise RuntimeError("SYNTHETIC_PROBE_FAILED")

    set_mode(monkeypatch, "fast")
    monkeypatch.setattr(embedders, "FastEmbedEmbedder", lambda: probe)
    created = track_created_memory(monkeypatch)
    with pytest.raises(ValueError, match="EMBEDDER_PROBE_FAILED"):
        with opened_server(db):
            pass
    assert len(calls) == 1
    assert_memory_closed(created)
    assert read_vector_snapshot(db) == before


def test_vector_scan_error_closes_connection_and_never_serves(monkeypatch, tmp_path):
    import sqlite3
    db = tmp_path / "scan-error.db"
    seed_vector_dimensions(db, [256])
    real_connections = []
    attempts = []

    class FailingRead:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, sql, *args):
            attempts.append(sql)
            raise sqlite3.OperationalError("SYNTHETIC_DIMENSION_SCAN_FAILED")

        def close(self):
            self.connection.close()

    def memory_factory(*args, **kwargs):
        memory = Memory(*args, **kwargs)
        real_connections.append(memory.store.con)
        memory.store.con = FailingRead(memory.store.con)
        return memory

    monkeypatch.setattr(mcp_server, "Memory", memory_factory)
    with pytest.raises(sqlite3.OperationalError, match="SYNTHETIC_DIMENSION_SCAN_FAILED"):
        with opened_server(db):
            pass
    assert len(real_connections) == 1 and len(attempts) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        real_connections[0].execute("SELECT 1")


@pytest.mark.parametrize("mode", FAST_MODES)
def test_explicit_fast_loader_failure_preserves_existing_384_store(monkeypatch, tmp_path, mode):
    db = tmp_path / "existing-fast.db"
    seed_vector_dimensions(db, [384])
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    memory_calls = []

    def unavailable():
        raise RuntimeError("SYNTHETIC_FAST_UNAVAILABLE")

    def forbidden(*args, **kwargs):
        memory_calls.append(True)
        raise AssertionError("Memory must not open after explicit loader failure")

    set_mode(monkeypatch, mode)
    monkeypatch.setattr(embedders, "FastEmbedEmbedder", unavailable)
    monkeypatch.setattr(mcp_server, "Memory", forbidden)
    with pytest.raises(RuntimeError, match="FAST_EMBEDDER_UNAVAILABLE"):
        mcp_server.Server(str(db))
    assert not memory_calls
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("mode,dimensions,denied", [
    (None, [384], True), ("hash", [384], True), ("fast", [256], True),
    ("hash", [256, 384], True), ("fast", [384, 256], True),
    (None, [256], False), ("fast", [384], False),
])
def test_real_stdio_dimension_barrier_precedes_initialize_and_remember(tmp_path, mode, dimensions, denied):
    db = tmp_path / "stdio.db"
    seed_vector_dimensions(db, dimensions)
    before = read_vector_snapshot(db)
    process, actual_db, imported, constructed = run_stdio_process(tmp_path, mode)
    assert actual_db == db
    if denied:
        assert process.returncode != 0
        assert "EMBEDDER_DIMENSION_MISMATCH" in process.stderr
        assert not process.stdout.strip()
        assert read_vector_snapshot(db) == before
    else:
        assert process.returncode == 0, process.stderr
        replies = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
        assert [r["id"] for r in replies] == [1, 2]
        assert not replies[1]["result"].get("isError")
        assert len(read_vector_snapshot(db)) == len(before) + 1
    assert constructed.exists() is (mode == "fast")


@pytest.mark.parametrize("seeded", [False, True])
def test_real_stdio_fast_import_failure_has_no_ready_response_or_fallback(tmp_path, seeded):
    db = tmp_path / "stdio.db"
    if seeded:
        seed_vector_dimensions(db, [384])
        before = read_vector_snapshot(db)
    process, _, _, _ = run_stdio_process(tmp_path, "fast", loader_failure=True)
    assert process.returncode != 0
    assert "FAST_EMBEDDER_UNAVAILABLE" in process.stderr
    assert not process.stdout.strip()
    if seeded:
        assert read_vector_snapshot(db) == before
    else:
        assert not db.exists()
