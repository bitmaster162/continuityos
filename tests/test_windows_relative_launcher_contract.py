from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "native" / "windows" / "sovereign_twin_launcher.c"
STARTER = ROOT / "native" / "windows" / "sovereign_twin_start.c"


@pytest.mark.skipif(
    not LAUNCHER.is_file(),
    reason="native Windows launcher source is repo-only and is not shipped in the wheel",
)
def test_runtime_launcher_is_location_relative_shell_free_and_bytecode_free():
    text = LAUNCHER.read_text(encoding="utf-8")
    assert "GetModuleFileNameW" in text
    assert 'L"%ls\\\\python.exe"' in text
    assert "CreateProcessW" in text
    assert "continuityos.sovereign_twin_cli" in text
    assert " -B -I -m " in text
    assert "__pycache__" in text
    assert "system(" not in text
    assert "ShellExecute" not in text
    assert "runtime-venv" not in text
    assert "AppData" not in text
    assert "C:\\\\Users" not in text


@pytest.mark.skipif(
    not STARTER.is_file(),
    reason="native Windows stable starter source is repo-only and is not shipped in the wheel",
)
def test_stable_starter_strictly_binds_complete_v3_pointer():
    text = STARTER.read_text(encoding="utf-8")
    assert 'SOURCE_SCHEMA "sovereign-twin.windows-runtime-source/v3"' in text
    assert "#define EXPECTED_FIELDS 18" in text
    assert "parse_pointer_json" in text
    assert "seen_mask" in text
    assert "field_id" in text
    assert "find_value(" not in text
    assert "json_bool_false(" not in text
    assert "parse_exact_false" in text
    assert "append_codepoint_utf8" in text

    for field in (
        "schema",
        "repository",
        "source_sha",
        "installed_at_utc",
        "python",
        "twin_executable",
        "memory_db",
        "admission_queue",
        "llm_server",
        "ui",
        "fast_model",
        "deep_model",
        "embedding_model",
        "execution_authority",
        "can_execute",
        "memory_activated_at_utc",
        "memory_manifest",
        "memory_embedding_dimension",
    ):
        assert f'"{field}"' in text

    assert 'strcmp(rp.execution_authority, "NONE") == 0' in text
    assert "rp.can_execute != 0" in text
    assert "parse_loopback_url(rp.llm_server" in text
    assert "parse_loopback_url(rp.ui" in text
    assert "memory_manifest" in text
    assert "memory_embedding_dimension" in text
    assert "_wcsicmp(python_root, twin_root) != 0" in text

    assert 'L"--base-url"' in text
    assert 'L"--embedding-model"' in text
    assert 'L"--admission-queue"' in text
    assert 'L"SOVEREIGN_TWIN_FAST_MODEL"' in text
    assert 'L"SOVEREIGN_TWIN_DEEP_MODEL"' in text
    assert 'ShellExecuteW(NULL, L"open", ui' in text
    assert 'L"--serve"' in text
    assert 'L"--open"' in text
    assert 'L"--status"' in text
    assert "CreateProcessW" in text

    assert "powershell" not in text.lower()
    assert "runtime-venv" not in text
    assert "AppData" not in text
