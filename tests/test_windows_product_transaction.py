from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import zipfile

import pytest

from continuityos.windows_product_transaction import (
    RUNTIME_PACKAGE_SCHEMA,
    RUNTIME_SOURCE_SCHEMA,
    canonical_tree_lines,
    canonical_tree_sha256,
    sha256_file,
    stage_validate,
    validate_runtime_package,
)

try:
    from tools.build_windows_runtime import build_runtime
except ModuleNotFoundError:
    # Wheel-only CI deliberately removes the repository source tree from sys.path.
    # The builder is repo tooling and is intentionally not shipped in the wheel.
    build_runtime = None

SOURCE_SHA = "1" * 40


def _builder_or_skip():
    if build_runtime is None:
        pytest.skip("repo-only Windows runtime builder is not packaged in wheel")
    return build_runtime


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _physical(path: Path) -> dict[str, tuple[bool, int | None, str | None]]:
    out = {}
    for p in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm"), Path(str(path) + "-journal")):
        if p.exists():
            out[str(p)] = (True, p.stat().st_size, _sha(p))
        else:
            out[str(p)] = (False, None, None)
    return out


def _fake_python_runtime(tmp_path: Path, *, embeddable: bool = False) -> Path:
    root = tmp_path / "python-runtime"
    root.mkdir()
    (root / "python.exe").write_bytes(b"MZ-fake-python")
    (root / "python311.dll").write_bytes(b"MZ-fake-python-dll")
    (root / "Lib").mkdir()
    if embeddable:
        (root / "python311._pth").write_text("python311.zip\n.\n#import site\n", encoding="utf-8")
    return root


def _fake_wheel(tmp_path: Path, version: str = "0.10.3") -> Path:
    wheel = tmp_path / f"continuityos-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(
            "continuityos/sovereign_twin_runtime.py",
            "EXECUTION_AUTHORITY = 'NONE'\nCAN_EXECUTE = False\n",
        )
        zf.writestr("continuityos/sovereign_twin_cli.py", "def main(): return 0\n")
        zf.writestr("continuityos/__init__.py", "__version__ = '0.10.3'\n")
        zf.writestr(
            f"continuityos-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: continuityos\nVersion: {version}\n\n",
        )
    return wheel


def _built_runtime(tmp_path: Path) -> Path:
    """Create a valid packaged-runtime fixture without repo-only build tooling."""
    build_id = f"0.10.3+{SOURCE_SHA[:12]}-win-x64"
    runtime = tmp_path / "runtimes" / build_id
    runtime.mkdir(parents=True)
    (runtime / "python.exe").write_bytes(b"MZ-fake-python")
    (runtime / "python311.dll").write_bytes(b"MZ-fake-python-dll")

    launcher = runtime / "Scripts" / "sovereign-twin.exe"
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"MZ-relative-launcher-fixture")

    module = runtime / "Lib" / "site-packages" / "continuityos" / "sovereign_twin_runtime.py"
    module.parent.mkdir(parents=True)
    module.write_text("EXECUTION_AUTHORITY = 'NONE'\nCAN_EXECUTE = False\n", encoding="utf-8")

    package = {
        "schema": RUNTIME_PACKAGE_SCHEMA,
        "build_id": build_id,
        "package_version": "0.10.3",
        "source_sha": SOURCE_SHA,
        "architecture": "win-x64",
        "wheel_sha256": "3" * 64,
        "python_path_config": None,
        "runtime_tree_sha256": "0" * 64,
        "runtime_module_sha256": sha256_file(module),
        "launcher_sha256": sha256_file(launcher),
        "runtime_source_schema_supported": [RUNTIME_SOURCE_SCHEMA],
        "memory_embedding_dimensions_supported": [768],
        "execution_authority": "NONE",
        "can_execute": False,
    }
    metadata = runtime / "runtime-package.json"
    metadata.write_text(json.dumps(package, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    package["runtime_tree_sha256"] = canonical_tree_sha256(runtime)
    metadata.write_text(json.dumps(package, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    (runtime / "SHA256SUMS").write_text(
        "\n".join(canonical_tree_lines(runtime)) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return runtime


def _live_pointer(
    tmp_path: Path,
    *,
    dimension: int = 768,
    authority: str = "NONE",
    can_execute: bool = False,
    memory_db: Path | None = None,
) -> Path:
    active = tmp_path / "active-r3"
    active.mkdir(exist_ok=True)
    python = active / "python.exe"
    twin = active / "sovereign-twin.exe"
    python.write_bytes(b"python")
    twin.write_bytes(b"twin")

    memory = memory_db or (tmp_path / "memory.db")
    if memory_db is None:
        con = sqlite3.connect(memory)
        try:
            con.execute("create table items (id integer primary key, vec blob)")
            con.commit()
        finally:
            con.close()

    memory_manifest = tmp_path / "memory.manifest.json"
    memory_manifest.write_text("{}\n", encoding="utf-8")
    pointer = tmp_path / "runtime-source.json"
    obj = {
        "schema": RUNTIME_SOURCE_SCHEMA,
        "repository": "bitmaster162/continuityos",
        "source_sha": "2" * 40,
        "installed_at_utc": "2026-08-29T00:00:00Z",
        "python": str(python),
        "twin_executable": str(twin),
        "memory_db": str(memory),
        "admission_queue": str(tmp_path / "twin-admissions.jsonl"),
        "llm_server": "http://127.0.0.1:1234",
        "ui": "http://127.0.0.1:8765",
        "fast_model": "qwen3.5-4b",
        "deep_model": "qwen3.6-35b-a3b",
        "embedding_model": "text-embedding-nomic-embed-text-v1.5",
        "execution_authority": authority,
        "can_execute": can_execute,
        "memory_activated_at_utc": "2026-08-29T00:00:00Z",
        "memory_manifest": str(memory_manifest),
        "memory_embedding_dimension": dimension,
    }
    pointer.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    return pointer


def test_builder_creates_versioned_immutable_shape_and_validator_accepts(tmp_path: Path):
    builder = _builder_or_skip()
    py = _fake_python_runtime(tmp_path)
    wheel = _fake_wheel(tmp_path)
    launcher = tmp_path / "sovereign-twin.exe"
    launcher.write_bytes(b"MZ-relative-launcher-fixture")
    result = builder(
        python_runtime=py,
        wheel=wheel,
        launcher=launcher,
        output_root=tmp_path / "runtimes",
        source_sha=SOURCE_SHA,
    )
    runtime = Path(result["runtime_root"])
    assert runtime.name == f"0.10.3+{SOURCE_SHA[:12]}-win-x64"
    assert (runtime / "python.exe").is_file()
    assert (runtime / "python311.dll").is_file()
    assert (runtime / "Scripts" / "sovereign-twin.exe").is_file()
    assert (runtime / "Lib" / "site-packages" / "continuityos" / "sovereign_twin_runtime.py").is_file()
    assert (runtime / "SHA256SUMS").is_file()

    package = json.loads((runtime / "runtime-package.json").read_text(encoding="utf-8"))
    assert package["schema"] == RUNTIME_PACKAGE_SCHEMA
    assert package["source_sha"] == SOURCE_SHA
    assert package["execution_authority"] == "NONE"
    assert package["can_execute"] is False

    checked = validate_runtime_package(runtime)
    assert checked["ok"] is True
    assert checked["build_id"] == runtime.name
    assert checked["runtime_tree_sha256"] == package["runtime_tree_sha256"]
    assert len(checked["sha256sums_sha256"]) == 64


def test_builder_normalizes_embeddable_python_path_for_bundled_site_packages(tmp_path: Path):
    builder = _builder_or_skip()
    py = _fake_python_runtime(tmp_path, embeddable=True)
    wheel = _fake_wheel(tmp_path)
    launcher = tmp_path / "sovereign-twin.exe"
    launcher.write_bytes(b"MZ-relative-launcher-fixture")
    result = builder(
        python_runtime=py,
        wheel=wheel,
        launcher=launcher,
        output_root=tmp_path / "runtimes",
        source_sha=SOURCE_SHA,
    )
    runtime = Path(result["runtime_root"])
    pth = (runtime / "python311._pth").read_text(encoding="utf-8").splitlines()
    assert "Lib\\site-packages" in pth
    assert "import site" in pth
    package = json.loads((runtime / "runtime-package.json").read_text(encoding="utf-8"))
    assert package["python_path_config"] == "python311._pth"
    validate_runtime_package(runtime)


def test_builder_is_content_deterministic_across_output_roots(tmp_path: Path):
    builder = _builder_or_skip()
    py = _fake_python_runtime(tmp_path, embeddable=True)
    wheel = _fake_wheel(tmp_path)
    launcher = tmp_path / "sovereign-twin.exe"
    launcher.write_bytes(b"MZ-relative-launcher-fixture")
    first = builder(
        python_runtime=py, wheel=wheel, launcher=launcher,
        output_root=tmp_path / "out-a", source_sha=SOURCE_SHA,
    )
    second = builder(
        python_runtime=py, wheel=wheel, launcher=launcher,
        output_root=tmp_path / "out-b", source_sha=SOURCE_SHA,
    )
    a = Path(first["runtime_root"])
    b = Path(second["runtime_root"])
    assert (a / "runtime-package.json").read_bytes() == (b / "runtime-package.json").read_bytes()
    assert (a / "SHA256SUMS").read_bytes() == (b / "SHA256SUMS").read_bytes()
    assert first["runtime_tree_sha256"] == second["runtime_tree_sha256"]


def test_builder_refuses_to_overwrite_existing_runtime(tmp_path: Path):
    builder = _builder_or_skip()
    py = _fake_python_runtime(tmp_path)
    wheel = _fake_wheel(tmp_path)
    launcher = tmp_path / "sovereign-twin.exe"
    launcher.write_bytes(b"MZ-relative-launcher-fixture")
    first = builder(
        python_runtime=py,
        wheel=wheel,
        launcher=launcher,
        output_root=tmp_path / "runtimes",
        source_sha=SOURCE_SHA,
    )
    runtime = Path(first["runtime_root"])
    with pytest.raises(ValueError, match="runtime build already exists"):
        builder(
            python_runtime=py,
            wheel=wheel,
            launcher=launcher,
            output_root=tmp_path / "runtimes",
            source_sha=SOURCE_SHA,
        )
    assert runtime.is_dir()


def test_validator_detects_payload_tamper(tmp_path: Path):
    runtime = _built_runtime(tmp_path)
    module = runtime / "Lib" / "site-packages" / "continuityos" / "sovereign_twin_runtime.py"
    module.write_text(module.read_text(encoding="utf-8") + "# tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="module SHA mismatch"):
        validate_runtime_package(runtime)


def test_validator_detects_sha256sums_tamper(tmp_path: Path):
    runtime = _built_runtime(tmp_path)
    sums = runtime / "SHA256SUMS"
    sums.write_text(sums.read_text(encoding="utf-8") + "# tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA256SUMS content mismatch"):
        validate_runtime_package(runtime)


def test_stage_validate_is_read_only_and_preserves_live_memory(tmp_path: Path):
    runtime = _built_runtime(tmp_path)
    pointer = _live_pointer(tmp_path)
    pointer_before = _sha(pointer)
    pointer_bytes_before = pointer.read_bytes()
    live_obj = json.loads(pointer.read_text(encoding="utf-8"))
    memory = Path(live_obj["memory_db"])
    physical_before = _physical(memory)

    receipt = stage_validate(runtime, pointer)

    assert receipt["ok"] is True
    assert receipt["effect"] == "READ_ONLY_ZERO_EXTERNAL_EFFECTS"
    assert receipt["activation_performed"] is False
    assert receipt["pointer_switch_performed"] is False
    assert receipt["memory_mutated"] is False
    assert receipt["execution_authority"] == "NONE"
    assert receipt["can_execute"] is False
    assert receipt["live"]["memory_quick_check"].lower() == "ok"
    assert receipt["live"]["sqlite_open_mode"] == "mode=ro&immutable=1"
    assert receipt["live"]["sqlite_physical_files_unchanged"] is True
    assert _sha(pointer) == pointer_before
    assert pointer.read_bytes() == pointer_bytes_before
    assert _physical(memory) == physical_before


def test_stage_validate_fails_closed_on_pending_wal_without_touching_files(tmp_path: Path):
    runtime = _built_runtime(tmp_path)
    memory = tmp_path / "wal-memory.db"
    con = sqlite3.connect(memory)
    try:
        assert con.execute("pragma journal_mode=wal").fetchone()[0].lower() == "wal"
        con.execute("create table items (id integer primary key, vec blob)")
        con.execute("insert into items(vec) values (?)", (b"x",))
        con.commit()
        wal = Path(str(memory) + "-wal")
        assert wal.is_file() and wal.stat().st_size > 0
        pointer = _live_pointer(tmp_path, memory_db=memory)
        before = _physical(memory)
        with pytest.raises(ValueError, match="refuses pending SQLite -wal content"):
            stage_validate(runtime, pointer)
        assert _physical(memory) == before
    finally:
        con.close()


def test_live_pointer_rejects_duplicate_json_keys(tmp_path: Path):
    runtime = _built_runtime(tmp_path)
    pointer = _live_pointer(tmp_path)
    raw = pointer.read_text(encoding="utf-8")
    raw = raw.replace('"can_execute": false,', '"can_execute": false,\n  "can_execute": false,', 1)
    pointer.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key: can_execute"):
        stage_validate(runtime, pointer)


def test_stage_validate_fails_closed_on_live_execution_authority(tmp_path: Path):
    runtime = _built_runtime(tmp_path)
    pointer = _live_pointer(tmp_path, authority="ALLOW")
    with pytest.raises(ValueError, match="execution_authority must be NONE"):
        stage_validate(runtime, pointer)


def test_stage_validate_fails_closed_on_embedding_dimension_mismatch(tmp_path: Path):
    runtime = _built_runtime(tmp_path)
    pointer = _live_pointer(tmp_path, dimension=1536)
    with pytest.raises(ValueError, match="does not declare support"):
        stage_validate(runtime, pointer)


def test_clean_install_preflight_allows_missing_pointer(tmp_path: Path):
    runtime = _built_runtime(tmp_path)
    receipt = stage_validate(runtime, tmp_path / "does-not-exist.json")
    assert receipt["ok"] is True
    assert receipt["live"]["present"] is False
    assert receipt["activation_performed"] is False
