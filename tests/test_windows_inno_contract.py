from __future__ import annotations

from pathlib import Path

import pytest

from continuityos.windows_product_transaction import _assert_memory_state_unchanged


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "packaging" / "windows" / "SovereignTwin.iss"


def _installer_text() -> str:
    if not INSTALLER.exists():
        pytest.skip(
            f"repo-only Windows installer source is not packaged in wheel: {INSTALLER.name}"
        )
    return INSTALLER.read_text(encoding="utf-8")


def _transaction_memory_states(memory_db: Path) -> tuple[dict, dict]:
    db = str(memory_db)
    manifest = str(memory_db.with_name("twin-memory-manifest.json"))
    physical = {
        db: {"present": True, "size": 36864, "mtime_ns": 1, "sha256": "a" * 64},
        db + "-wal": {"present": False},
        db + "-shm": {"present": False},
        db + "-journal": {"present": False},
    }
    before = {
        "memory_db": db,
        "memory_db_sha256": "a" * 64,
        "sqlite_physical_fingerprints": {key: dict(value) for key, value in physical.items()},
        "memory_manifest": manifest,
        "memory_manifest_sha256": "b" * 64,
    }
    after = {
        "memory_db": db,
        "memory_db_sha256": "a" * 64,
        "sqlite_physical_fingerprints": {key: dict(value) for key, value in physical.items()},
        "memory_manifest": manifest,
        "memory_manifest_binding": {"sha256": "b" * 64},
    }
    return before, after


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


def test_p1b_same_app_uninstall_identity_is_stable_and_append_only():
    text = _installer_text()

    assert "AppId=SovereignTwin.Windows" in text
    assert "UninstallLogMode=append" in text
    assert r"UninstallFilesDir={app}\uninstall" in text

    uninstall_dir_line = next(
        line for line in text.splitlines() if line.startswith("UninstallFilesDir=")
    )
    assert "{#RuntimeBuildId}" not in uninstall_dir_line
    assert "UninstallDisplayName=Sovereign Twin" in text


def test_p1b_autostart_is_current_user_startup_only_and_preserves_preexisting_shortcut():
    text = _installer_text()
    autostart_line = next(
        line
        for line in text.splitlines()
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


def test_p1b_existing_install_entrypoints_are_preserved_during_same_app_upgrade():
    text = _installer_text()

    starter_line = next(
        line for line in text.splitlines() if 'DestName: "SovereignTwin-Start.exe"' in line
    )
    assert "onlyifdoesntexist" in starter_line

    start_menu_line = next(
        line
        for line in text.splitlines()
        if line.startswith('Name: "{group}\\Sovereign Twin"')
    )
    assert "Check: ShouldCreateStartMenuShortcut" in start_menu_line
    assert "Check: ShouldCreateAutostartShortcut" in text


def test_p1b_registers_only_stable_starter_entrypoints():
    text = _installer_text()
    icon_lines = [line for line in text.splitlines() if line.startswith("Name: ")]

    assert len(icon_lines) == 2
    assert all('Filename: "{app}\\SovereignTwin-Start.exe"' in line for line in icon_lines)
    assert any('Parameters: "--serve"' in line for line in icon_lines)
    assert any('Parameters: "--open"' in line for line in icon_lines)


def test_p1c_activation_is_opt_in_and_delegated_to_packaged_python():
    text = _installer_text()
    lower = text.lower()

    assert "#ifndef P1CEnableExistingBindingActivation" in text
    assert '#define P1CEnableExistingBindingActivation "0"' in text
    assert '#if P1CEnableExistingBindingActivation == "1"' in text
    assert "procedure CurStepChanged(CurStep: TSetupStep);" in text
    assert "if CurStep <> ssPostInstall then" in text
    assert "FileExists(PointerPath)" in text
    assert "windows_product_transaction --p1c-write activate" in text
    assert "ExecAndLogOutput(PythonExe, Params" in text
    assert "ewWaitUntilTerminated, ResultCode, nil)" in text
    assert "if ResultCode <> 0 then" in text
    assert "Exec(PythonExe, Params" not in text
    assert "RaiseException('P1C activation helper failed rc='" not in text
    assert "[Run]" not in text

    # Inno may locate the pointer and delegate the transaction, but it must not
    # recreate the runtime-source schema or memory/model binding itself.
    assert "memory_db" not in lower
    assert "llm_server" not in lower
    assert "fast_model" not in lower
    assert "deep_model" not in lower
    assert "embedding_model" not in lower
    assert "execution_authority" not in lower
    assert "can_execute" not in lower
    assert "powershell" not in lower
    assert "pip install" not in lower


def test_p1c_helper_failure_is_logged_and_forces_nonzero_setup_exit():
    text = _installer_text()

    assert "P1CActivationFailureExitCode = 90;" in text
    assert "P1CActivationFailed: Boolean;" in text
    assert "procedure MarkP1CActivationFailure" in text
    assert "P1CActivationFailed := True;" in text
    assert "function GetCustomSetupExitCode: Integer;" in text
    assert "if P1CActivationFailed then" in text
    assert "Result := P1CActivationFailureExitCode;" in text
    assert "P1C fail-closed custom setup exit code=" in text
    assert "P1C activation helper output capture failed:" in text
    assert "GetExceptionMessage" in text
    assert "P1C activation helper failed rc=" in text


def test_p1c_transaction_compare_tolerates_only_shm_coordination_drift(tmp_path: Path):
    before, after = _transaction_memory_states(tmp_path / "twin.db")
    shm = str(tmp_path / "twin.db-shm")
    after["sqlite_physical_fingerprints"][shm] = {
        "present": True,
        "size": 32768,
        "mtime_ns": 2,
        "sha256": "c" * 64,
    }

    _assert_memory_state_unchanged(before, after)

    # Receipts still retain the physical -shm fingerprint; only the transaction-wide
    # cross-process equality comparison normalizes this volatile coordination state.
    assert after["sqlite_physical_fingerprints"][shm]["present"] is True


@pytest.mark.parametrize("suffix", ("", "-wal", "-journal"))
def test_p1c_transaction_compare_rejects_db_wal_and_journal_drift(
    tmp_path: Path, suffix: str
):
    before, after = _transaction_memory_states(tmp_path / "twin.db")
    key = str(tmp_path / "twin.db") + suffix
    after["sqlite_physical_fingerprints"][key] = {
        "present": True,
        "size": 1,
        "mtime_ns": 2,
        "sha256": "d" * 64,
    }

    with pytest.raises(ValueError, match="memory physical state changed"):
        _assert_memory_state_unchanged(before, after)


def test_p1c_transaction_compare_rejects_db_and_manifest_content_drift(tmp_path: Path):
    before, after = _transaction_memory_states(tmp_path / "twin.db")
    after["memory_db_sha256"] = "e" * 64
    with pytest.raises(ValueError, match="memory physical state changed"):
        _assert_memory_state_unchanged(before, after)

    before, after = _transaction_memory_states(tmp_path / "twin.db")
    after["memory_manifest_binding"]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="memory physical state changed"):
        _assert_memory_state_unchanged(before, after)


def test_p1c_default_build_remains_p1b_stage_only_without_activation_define():
    text = _installer_text()

    define_line = next(
        line for line in text.splitlines() if "#define P1CEnableExistingBindingActivation" in line
    )
    assert define_line.strip().endswith('"0"')
    assert 'Excludes: "runtime-source.json"' in text
    assert "P1C activation skipped: no existing runtime-source.json binding" in text


def test_p1b_uninstall_entry_present_without_manual_autostart_delete_semantics():
    text = _installer_text()

    assert "Uninstallable=yes" in text
    assert "CreateUninstallRegKey=yes" in text
    assert "UninstallLogMode=append" in text
    assert r"UninstallFilesDir={app}\uninstall" in text
    assert "CurUninstallStepChanged" not in text
    assert "DeleteFile(" not in text
