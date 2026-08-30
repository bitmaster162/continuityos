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
    assert 'DestDir: "{app}\\runtimes\\{#RuntimeBuildId}"' in text
    assert 'DestName: "SovereignTwin-Start.exe"' in text
    assert "onlyifdoesntexist" in text
    assert "recursesubdirs" in text
    assert "createallsubdirs" in text


def test_p1b_autostart_is_current_user_startup_only_and_preserves_preexisting_shortcut():
    text = _installer_text()
    autostart_line = next(
        line for line in text.splitlines()
        if line.startswith('Name: "{userstartup}\\Sovereign Twin UI"')
    )

    assert 'Filename: "{app}\\SovereignTwin-Start.exe"' in autostart_line
    assert 'Parameters: "--serve"' in autostart_line
    assert 'WorkingDir: "{app}"' in autostart_line
    assert "Check: ShouldCreateAutostartShortcut" in autostart_line
    assert "function ShouldCreateAutostartShortcut: Boolean;" in text
    assert (
        "Result := not FileExists(ExpandConstant("
        "'{userstartup}\\Sovereign Twin UI.lnk'));"
    ) in text
    assert "Preserving pre-existing per-user Startup shortcut" in text

    lower = text.lower()
    assert "schtasks.exe" not in lower
    assert "<logontrigger>" not in lower
    assert "interactivetoken" not in lower
    assert "/ru " not in lower
    assert "/rp " not in lower


def test_p1b_autostart_uninstall_ownership_is_inno_logged_not_manual_global_cleanup():
    text = _installer_text()

    assert r"{userstartup}\Sovereign Twin UI" in text
    assert "ShouldCreateAutostartShortcut" in text
    assert "installer-state" not in text
    assert "DeleteOwnedAutostartTask" not in text
    assert "CurUninstallStepChanged" not in text
    assert "/Delete /F /TN" not in text


def test_p1b_existing_install_files_and_uninstall_logs_are_isolated():
    text = _installer_text()

    assert "UninstallLogMode=new" in text
    assert r"UninstallFilesDir={app}\uninstall\{#RuntimeBuildId}" in text
    starter_line = next(
        line for line in text.splitlines() if 'DestName: "SovereignTwin-Start.exe"' in line
    )
    assert "onlyifdoesntexist" in starter_line

    start_menu_line = next(
        line for line in text.splitlines() if line.startswith('Name: "{group}\\Sovereign Twin"')
    )
    assert "Check: ShouldCreateStartMenuShortcut" in start_menu_line


def test_p1b_registers_only_stable_starter_entrypoints():
    text = _installer_text()
    icon_lines = [line for line in text.splitlines() if line.startswith("Name: ")]

    assert len(icon_lines) == 2
    assert all('Filename: "{app}\\SovereignTwin-Start.exe"' in line for line in icon_lines)
    assert any('Parameters: "--serve"' in line for line in icon_lines)
    assert any('Parameters: "--open"' in line for line in icon_lines)


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


def test_p1b_uninstall_entry_present_without_p1c_or_manual_autostart_delete_semantics():
    text = _installer_text()

    assert "Uninstallable=yes" in text
    assert "CreateUninstallRegKey=yes" in text
    assert r"UninstallFilesDir={app}\uninstall\{#RuntimeBuildId}" in text
    assert "CurUninstallStepChanged" not in text
    assert "DeleteFile(" not in text
