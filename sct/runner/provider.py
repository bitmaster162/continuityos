
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
import json
import subprocess

from ..errors import BenchError


class PredictionRunner(Protocol):
    def predict(self, request: Mapping[str, Any], *, arm: str) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class SubprocessJsonRunner:
    """Provider-agnostic runner seam.

    The command receives one request JSON object on stdin and MUST emit exactly
    one JSON object on stdout. SCT never retries automatically.
    """
    command: Sequence[str]
    timeout_seconds: float = 120.0

    def predict(self, request: Mapping[str, Any], *, arm: str) -> Mapping[str, Any]:
        if not self.command:
            raise BenchError("runner command is empty")
        payload = json.dumps({"arm": arm, "request": request}, ensure_ascii=False, sort_keys=True)
        try:
            proc = subprocess.run(
                list(self.command),
                input=payload,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BenchError(f"PROVIDER_RUNNER_FAILURE: {exc}") from exc
        if proc.returncode != 0:
            err = (proc.stderr or "").strip()[:500]
            raise BenchError(f"PROVIDER_RUNNER_FAILURE: exit={proc.returncode} {err}")
        stdout = (proc.stdout or "").strip()
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise BenchError("PROVIDER_RUNNER_FAILURE: stdout is not one JSON object") from exc
        if not isinstance(data, Mapping):
            raise BenchError("PROVIDER_RUNNER_FAILURE: response must be a JSON object")
        return data


@dataclass(frozen=True)
class FixtureRunner:
    """Deterministic dry-run runner. Never use for valid LIVE cases."""
    by_arm: Mapping[str, Mapping[str, Any]]

    def predict(self, request: Mapping[str, Any], *, arm: str) -> Mapping[str, Any]:
        try:
            return dict(self.by_arm[arm])
        except KeyError as exc:
            raise BenchError(f"fixture missing arm {arm}") from exc
