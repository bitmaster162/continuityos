from __future__ import annotations

from dataclasses import dataclass
import json
import math
import subprocess
from typing import Any, Mapping, Protocol, Sequence

from ..canon import sha256_obj
from ..errors import BenchError
from .provider import ProviderConfigurationError, ProviderResponseMalformedJsonError, ProviderTransportError, _typed_failure


class AllowedTokenLogitRunner(Protocol):
    def allowed_token_logits(self, request: Mapping[str, Any], *, aliases: Sequence[str]) -> Mapping[str, float]: ...


@dataclass(frozen=True)
class SubprocessLogitRunner:
    """One-shot raw-logit runner. Arm identity is never forwarded and SCT never retries."""

    command: Sequence[str]
    timeout_seconds: float = 120.0

    def allowed_token_logits(
        self,
        request: Mapping[str, Any],
        *,
        aliases: Sequence[str],
        alias_token_ids: Mapping[str, int] | None = None,
    ) -> Mapping[str, float]:
        if not self.command:
            raise ProviderConfigurationError("logit runner command is empty")
        allowed = tuple(str(x) for x in aliases)
        if len(allowed) < 2 or len(set(allowed)) != len(allowed):
            raise BenchError("allowed aliases must be distinct")
        if alias_token_ids is None or set(alias_token_ids) != set(allowed):
            raise ProviderConfigurationError("exact alias_token_ids are required for R13 subprocess logits")
        token_ids: dict[str, int] = {}
        for alias in allowed:
            token_id = alias_token_ids[alias]
            if isinstance(token_id, bool) or not isinstance(token_id, int) or token_id < 0:
                raise ProviderConfigurationError("alias token IDs must be non-negative integers")
            token_ids[alias] = token_id
        payload = json.dumps(
            {
                "mode": "allowed_token_logits",
                "request": dict(request),
                "allowed_aliases": allowed,
                "allowed_alias_token_ids": token_ids,
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
        used_ids = data.get("used_alias_token_ids")
        if not isinstance(logits, Mapping) or set(logits) != set(allowed):
            raise ProviderResponseMalformedJsonError("allowed_token_logits must contain exact alias set")
        if not isinstance(used_ids, Mapping) or dict(used_ids) != token_ids:
            raise ProviderResponseMalformedJsonError("runner must echo exact used_alias_token_ids")
        clean: dict[str, float] = {}
        for alias in allowed:
            value = logits[alias]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise ProviderResponseMalformedJsonError("allowed-token logits must be finite numeric values")
            clean[alias] = float(value)
        return clean


@dataclass(frozen=True)
class ManifestBoundLogitRunner:
    """Bind every real subprocess call to the alias token IDs sealed in the model manifest."""

    inner: SubprocessLogitRunner
    alias_token_ids: Mapping[str, int]

    @classmethod
    def from_model_manifest(cls, inner: SubprocessLogitRunner, model_manifest: Mapping[str, Any]):
        rows = model_manifest.get("alias_tokens")
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
            raise ProviderConfigurationError("sealed model manifest alias_tokens required")
        mapping: dict[str, int] = {}
        for row in rows:
            if not isinstance(row, Mapping):
                raise ProviderConfigurationError("alias_tokens entries must be objects")
            alias = str(row.get("alias", ""))
            token_id = row.get("token_id")
            if not alias or isinstance(token_id, bool) or not isinstance(token_id, int) or token_id < 0:
                raise ProviderConfigurationError("invalid sealed alias/token-id mapping")
            mapping[alias] = token_id
        return cls(inner=inner, alias_token_ids=mapping)

    def allowed_token_logits(self, request: Mapping[str, Any], *, aliases: Sequence[str]) -> Mapping[str, float]:
        allowed = tuple(str(x) for x in aliases)
        try:
            token_ids = {alias: self.alias_token_ids[alias] for alias in allowed}
        except KeyError as exc:
            raise ProviderConfigurationError("requested alias absent from sealed model manifest") from exc
        return self.inner.allowed_token_logits(request, aliases=allowed, alias_token_ids=token_ids)


class CapturingLogitRunner:
    """Evidence wrapper that records each exact raw-logit call without retrying it."""

    def __init__(self, inner):
        self.inner = inner
        self.records: list[dict[str, Any]] = []

    def allowed_token_logits(self, request: Mapping[str, Any], *, aliases: Sequence[str]) -> Mapping[str, float]:
        allowed = tuple(str(x) for x in aliases)
        token_source = getattr(self.inner, "alias_token_ids", None)
        if not isinstance(token_source, Mapping):
            raise ProviderConfigurationError("capturing R13 runner requires manifest-bound alias token IDs")
        try:
            token_ids = {alias: int(token_source[alias]) for alias in allowed}
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderConfigurationError("capturing R13 runner cannot resolve sealed alias token IDs") from exc
        logits = self.inner.allowed_token_logits(request, aliases=allowed)
        self.records.append({
            "ordinal": len(self.records) + 1,
            "request_sha256": sha256_obj(dict(request)),
            "request_envelope_sha256": request.get("envelope_sha256"),
            "allowed_aliases": allowed,
            "allowed_alias_token_ids": token_ids,
            "raw_allowed_token_logits": {alias: float(logits[alias]) for alias in allowed},
            "execution_authority": "NONE",
        })
        return logits
