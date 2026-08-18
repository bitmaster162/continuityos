from __future__ import annotations

from dataclasses import dataclass
import json
import math
import subprocess
from typing import Any, Mapping, Protocol, Sequence

from ..errors import BenchError
from .provider import ProviderConfigurationError, ProviderResponseMalformedJsonError, ProviderTransportError, _typed_failure


class AllowedTokenLogitRunner(Protocol):
    def allowed_token_logits(self, request: Mapping[str, Any], *, aliases: Sequence[str]) -> Mapping[str, float]: ...


@dataclass(frozen=True)
class SubprocessLogitRunner:
    """One-shot raw-logit runner. Arm identity is never forwarded and SCT never retries."""

    command: Sequence[str]
    timeout_seconds: float = 120.0

    def allowed_token_logits(self, request: Mapping[str, Any], *, aliases: Sequence[str]) -> Mapping[str, float]:
        if not self.command:
            raise ProviderConfigurationError("logit runner command is empty")
        allowed = tuple(str(x) for x in aliases)
        if len(allowed) < 2 or len(set(allowed)) != len(allowed):
            raise BenchError("allowed aliases must be distinct")
        payload = json.dumps(
            {
                "mode": "allowed_token_logits",
                "request": dict(request),
                "allowed_aliases": allowed,
                "execution_authority": "NONE",
                "can_execute": False,
            },
            ensure_ascii=True,
            sort_keys=True,
        )
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
            raise ProviderTransportError("logit runner subprocess timeout") from exc
        except OSError as exc:
            raise ProviderTransportError(f"logit runner subprocess OS failure: {exc}") from exc
        if proc.returncode != 0:
            raise _typed_failure(proc.stderr or "")
        stdout = (proc.stdout or "").strip()
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ProviderResponseMalformedJsonError("logit runner stdout is not one JSON object") from exc
        if not isinstance(data, Mapping):
            raise ProviderResponseMalformedJsonError("logit runner response must be a JSON object")
        logits = data.get("allowed_token_logits")
        if not isinstance(logits, Mapping) or set(logits) != set(allowed):
            raise ProviderResponseMalformedJsonError("allowed_token_logits must contain exact alias set")
        clean: dict[str, float] = {}
        for alias in allowed:
            value = logits[alias]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise ProviderResponseMalformedJsonError("allowed-token logits must be finite numeric values")
            clean[alias] = float(value)
        return clean
