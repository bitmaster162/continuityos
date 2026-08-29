from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "native" / "windows" / "sovereign_twin_launcher.c"
STARTER = ROOT / "native" / "windows" / "sovereign_twin_start.c"


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


def test_stable_starter_reads_v3_pointer_and_fails_closed_on_authority():
    text = STARTER.read_text(encoding="utf-8")
    assert 'SOURCE_SCHEMA "sovereign-twin.windows-runtime-source/v3"' in text
    assert 'json_string(json, "execution_authority")' in text
    assert 'strcmp(authority, "NONE") == 0' in text
    assert 'json_bool_false(json, "can_execute")' in text
    assert 'json_string(json, "twin_executable")' in text
    assert 'json_string(json, "memory_db")' in text
    assert 'json_string(json, "admission_queue")' in text
    assert 'json_string(json, "embedding_model")' in text
    assert 'L"--serve"' in text
    assert 'L"--open"' in text
    assert 'L"--status"' in text
    assert "CreateProcessW" in text
    assert "powershell" not in text.lower()
    assert "runtime-venv" not in text
    assert "AppData" not in text
