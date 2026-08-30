from __future__ import annotations

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "packaging" / "windows" / "SovereignTwin.iss"


def _installer_text() -> str:
    if not INSTALLER.exists():
        pytest.skip(
            f"repo-only Windows installer source is not packaged in wheel: {INSTALLER.name}"
        )
    return INSTALLER.read_text(encoding="utf-8")


def test_p1b_requires_explicit_prebuilt_runtime_inputs():
    text = _installer_text()

    for define in (
        "RuntimeRoot",
        "RuntimeBuildId",
        "StableStarter",
        "ProductVersion",
        "SourceSha",
        "OutputDir",
    ):
        assert f"#ifndef {define}" in text
        assert f"#error {define} define is required" in text


def test_p1b_is_per_user_and_stages_only_immutable_runtime_payload():
    text = _installer_text()

    assert "PrivilegesRequired=lowest" in text
    assert r"DefaultDirName={localappdata}\SovereignTwin" in text
    assert "ArchitecturesAllowed=x64compatible" in text
    assert "ArchitecturesInstallIn64BitMode=x64compatible" in text
    assert (
        'DestDir: "{app}\\runtimes\\{#RuntimeBuildId}"' in text
    )
    assert (
        'DestName: "SovereignTwin-Start.exe"' in text
    )
    assert "recursesubdirs" in text
    assert "createallsubdirs" in text


def test_p1b_registers_only_stable_starter_entrypoints():
    text = _installer_text()

    assert "ScheduledTaskName = 'SovereignTwin-UI';" in text
    assert r"{sys}\schtasks.exe" in text
    assert "/Create /F /SC ONLOGON /RL LIMITED" in text
    assert "--serve" in text
    assert "[Icons]" in text
    assert 'Filename: "{app}\\SovereignTwin-Start.exe"' in text
    assert 'Parameters: "--open"' in text


def test_p1b_schtasks_command_does_not_persist_literal_quote_characters_in_execute():
    text = _installer_text()

    create_block = text[text.index("procedure CreateAutostartTask;"):text.index("procedure DeleteAutostartTask;")]
    assert "'\" /TR \"' + Starter + ' --serve\"';" in create_block
    assert "\\\"' + Starter" not in create_block
    assert "Starter + '\\\"" not in create_block


def test_p1b_has_no_pointer_activation_or_memory_runtime_mutation_logic():
    text = _installer_text()
    lower = text.lower()

    pointer_lines = [line for line in text.splitlines() if "runtime-source.json" in line]
    assert len(pointer_lines) == 1
    assert "Excludes:" in pointer_lines[0]

    for forbidden in (
        ".continuityos",
        "powershell",
        "python.exe",
        "pip install",
        "--activate",
        "postbind",
        "rollback",
        "memory_db",
        "llm_server",
        "fast_model",
        "deep_model",
        "embedding_model",
    ):
        assert forbidden not in lower

    assert "[Run]" not in text
    assert "Start-Process" not in text


def test_p1b_uninstall_entry_and_task_cleanup_are_present_without_p1d_semantics():
    text = _installer_text()

    assert "Uninstallable=yes" in text
    assert "CreateUninstallRegKey=yes" in text
    assert "procedure DeleteAutostartTask;" in text
    assert "/Delete /F /TN" in text
    assert "procedure CurUninstallStepChanged" in text
    assert "CurUninstallStep = usUninstall" in text
