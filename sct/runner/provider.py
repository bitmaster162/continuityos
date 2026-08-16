from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence
import json
import re
import subprocess

from ..errors import BenchError


class PredictionRunner(Protocol):
    def predict(self, request: Mapping[str, Any], *, arm: str) -> Mapping[str, Any]: ...


class ProviderRunnerError(BenchError):
    """Safe typed provider failure; outer arena may expose only this class name."""


class ProviderConfigurationError(ProviderRunnerError):
    pass


class ProviderTransportError(ProviderRunnerError):
    pass


class ProviderResponseContractError(ProviderRunnerError):
    pass


class ProviderHTTP400Error(ProviderRunnerError):
    pass


class ProviderHTTP401Error(ProviderRunnerError):
    pass


class ProviderHTTP402Error(ProviderRunnerError):
    pass


class ProviderHTTP403Error(ProviderRunnerError):
    pass


class ProviderHTTP404Error(ProviderRunnerError):
    pass


class ProviderHTTP408Error(ProviderRunnerError):
    pass


class ProviderHTTP409Error(ProviderRunnerError):
    pass


class ProviderHTTP422Error(ProviderRunnerError):
    pass


class ProviderHTTP429Error(ProviderRunnerError):
    pass


class ProviderHTTP5xxError(ProviderRunnerError):
    pass


_HTTP_TYPES = {
    400: ProviderHTTP400Error,
    401: ProviderHTTP401Error,
    402: ProviderHTTP402Error,
    403: ProviderHTTP403Error,
    404: ProviderHTTP404Error,
    408: ProviderHTTP408Error,
    409: ProviderHTTP409Error,
    422: ProviderHTTP422Error,
    429: ProviderHTTP429Error,
}


def _safe_detail(stderr: str) -> str:
    """Keep a bounded diagnostic locally while redacting credential-shaped tokens."""
    text = " ".join((stderr or "").split())
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "sk-[REDACTED]", text)
    return text[:500]


def _typed_failure(stderr: str) -> ProviderRunnerError:
    detail = _safe_detail(stderr)
    lower = detail.lower()
    match = re.search(r"provider http (\d{3})", lower)
    if match:
        status = int(match.group(1))
        cls = _HTTP_TYPES.get(status, ProviderHTTP5xxError if 500 <= status <= 599 else ProviderRunnerError)
        return cls(detail or f"provider HTTP {status}")
    if "missing required environment variable" in lower:
        return ProviderConfigurationError(detail)
    if "provider transport failure" in lower:
        return ProviderTransportError(detail)
    if (
        "response did not contain one json prediction object" in lower
        or "provider prediction is not a json object" in lower
        or "provider message content is not text" in lower
    ):
        return ProviderResponseContractError(detail)
    return ProviderRunnerError(detail or "provider subprocess failed")


@dataclass(frozen=True)
class SubprocessJsonRunner:
    """Provider-agnostic one-shot runner. SCT never retries automatically."""

    command: Sequence[str]
    timeout_seconds: float = 120.0

    def predict(self, request: Mapping[str, Any], *, arm: str) -> Mapping[str, Any]:
        if not self.command:
            raise ProviderConfigurationError("runner command is empty")

        # Arm identity is deliberately NOT forwarded to the provider process.
        # ASCII-escaped JSON plus explicit UTF-8 pipes makes transport deterministic
        # on Windows even when prompts contain characters outside cp1252/OEM pages.
        payload = json.dumps(request, ensure_ascii=True, sort_keys=True)

        try:
            proc = subprocess.run(
                list(self.command),
                input=payload,
                text=True,
                encoding="utf-8",
                errors="strict",
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProviderTransportError("provider subprocess timeout") from exc
        except OSError as exc:
            raise ProviderTransportError(f"provider subprocess OS failure: {exc}") from exc

        if proc.returncode != 0:
            raise _typed_failure(proc.stderr or "")

        stdout = (proc.stdout or "").strip()
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ProviderResponseContractError("provider stdout is not one JSON object") from exc
        if not isinstance(data, Mapping):
            raise ProviderResponseContractError("provider response must be a JSON object")
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
