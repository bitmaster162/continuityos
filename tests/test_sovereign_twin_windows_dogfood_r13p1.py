from pathlib import Path


SCRIPT = Path("scripts/windows/SovereignTwin-Dogfood-R13P1.ps1")


def _text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_r13p1_harness_is_exact_sha_bound_and_authority_none():
    text = _text()
    assert 'b781108be9c8c7be3d1c7169642b9ef0d657289c' in text
    assert 'edacb54409ebcf355f7a57b3e34190c79dd6c7cd' in text
    assert "execution_authority -eq \"NONE\"" in text
    assert "can_execute" in text
    assert "capital_permission = 'DENY'" in text


def test_r13p1_harness_checks_raw_empty_lms_json_without_false_array_wrapper():
    text = _text()
    assert "(& lms ps --json 2>&1 | Out-String).Trim()" in text
    assert "$compact -eq '[]'" in text
    assert "@(lms ps --json | ConvertFrom-Json)" not in text


def test_r13p1_harness_preserves_nomic_pointer_and_has_rollback_path():
    text = _text()
    assert "memory-nomic-768-*.db" in text
    assert "manifest DB pointer changed" in text
    assert "rollbackWheel" in text
    assert "$targetInstallAttempted = $true" in text
    assert "if ($targetInstallAttempted -and $rollbackWheel" in text
    assert "ROLLBACK=PASS" in text


def test_r13p1_harness_enforces_ascii_only_unicode_emission():
    text = _text()
    assert "ensure_ascii" not in text  # implementation check belongs to installed Python, not the harness source
    assert "-notmatch '[^\\x00-\\x7F]'" in text
    assert "Unicode round-trip failed" in text
    assert "Unicode was not escaped in CLI JSON" in text


def test_r13p1_harness_validates_two_pass_reasoning_off_contract():
    text = _text()
    assert "bounded_two_pass_reasoning_off" in text
    assert "pass_count -eq 2" in text
    assert "draft_max_output_tokens -eq 400" in text
    assert "final_max_output_tokens -eq 700" in text
    assert "reasoning_output_tokens -eq 0" in text
    assert "outside retrieved evidence" in text
