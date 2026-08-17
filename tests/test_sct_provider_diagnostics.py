from __future__ import annotations

from pathlib import Path
import sys

import pytest

from sct.errors import BenchError
from sct.runner.provider import (
    ProviderConfigurationError,
    ProviderHTTP401Error,
    ProviderHTTP404Error,
    ProviderHTTP429Error,
    ProviderResponseContractError,
    SubprocessJsonRunner,
)
from sct.dryrun import run_real_model_void_dryrun


def _script(tmp_path: Path, stderr: str, exit_code: int = 2) -> Path:
    p = tmp_path / "runner.py"
    p.write_text(
        "import sys\n"
        f"sys.stderr.write({stderr!r})\n"
        f"raise SystemExit({exit_code})\n",
        encoding="utf-8",
    )
    return p


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("SCT_PROVIDER_ERROR: provider HTTP 401: invalid key", ProviderHTTP401Error),
        ("SCT_PROVIDER_ERROR: provider HTTP 404: no compatible endpoint", ProviderHTTP404Error),
        ("SCT_PROVIDER_ERROR: provider HTTP 429: rate limited", ProviderHTTP429Error),
        (
            "SCT_PROVIDER_ERROR: provider response did not contain one JSON prediction object",
            ProviderResponseContractError,
        ),
        (
            "SCT_PROVIDER_ERROR: missing required environment variable: SCT_OPENAI_COMPAT_API_KEY",
            ProviderConfigurationError,
        ),
    ],
)
def test_subprocess_runner_classifies_provider_failure(tmp_path, stderr, expected):
    runner = SubprocessJsonRunner([sys.executable, "-S", str(_script(tmp_path, stderr))])
    with pytest.raises(expected):
        runner.predict({"x": 1}, arm="generic")


def test_secret_shaped_token_is_redacted(tmp_path):
    runner = SubprocessJsonRunner(
        [
            sys.executable,
            "-S",
            str(
                _script(
                    tmp_path,
                    "SCT_PROVIDER_ERROR: provider HTTP 401: "
                    "Bearer sk-or-v1-supersecret1234567890",
                )
            ),
        ]
    )
    with pytest.raises(ProviderHTTP401Error) as caught:
        runner.predict({"x": 1}, arm="generic")
    message = str(caught.value)
    assert "supersecret" not in message
    assert "[REDACTED]" in message


def test_outer_void_gate_surfaces_typed_failure_and_calls_once():
    class Failing:
        def __init__(self):
            self.calls = 0

        def predict(self, request, *, arm):
            self.calls += 1
            raise ProviderHTTP429Error("provider HTTP 429")

    runner = Failing()
    with pytest.raises(BenchError) as caught:
        run_real_model_void_dryrun(
            runner=runner,
            cases=10,
            provider="openrouter",
            model="example/model",
            model_version="v1",
            runner_command_sha256="0" * 64,
        )
    assert runner.calls == 1
    assert "ProviderHTTP429Error" in str(caught.value)
