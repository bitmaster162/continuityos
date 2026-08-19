"""Local-only Sovereign Twin runtime for LM Studio / llmster.

This module is a product/runtime bridge, not the R13 scientific evaluator.
It never grants execution authority and defaults to a loopback-only model server.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .memory import Memory

EXECUTION_AUTHORITY = "NONE"
DEFAULT_BASE_URL = "http://127.0.0.1:1234"


class LocalModelEndpointError(RuntimeError):
    """Raised when the model endpoint is unavailable or violates local-only policy."""


@dataclass(frozen=True)
class LocalModelProfile:
    model: str
    ttl_seconds: int
    max_tokens: int
    temperature: float


DEFAULT_PROFILES: dict[str, LocalModelProfile] = {
    "fast": LocalModelProfile(
        model=os.environ.get("SOVEREIGN_TWIN_FAST_MODEL", "qwen3.5-4b"),
        ttl_seconds=1800,
        max_tokens=1200,
        temperature=0.2,
    ),
    "deep": LocalModelProfile(
        model=os.environ.get("SOVEREIGN_TWIN_DEEP_MODEL", "qwen3.6-35b-a3b"),
        ttl_seconds=600,
        max_tokens=2200,
        temperature=0.15,
    ),
}


@dataclass(frozen=True)
class TwinEvidence:
    id: int
    namespace: str
    text: str
    score: float
    why: str


@dataclass(frozen=True)
class TwinAnswer:
    text: str
    model: str
    mode: str
    evidence: tuple[TwinEvidence, ...]
    execution_authority: str = EXECUTION_AUTHORITY
    can_execute: bool = False

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["evidence"] = [asdict(row) for row in self.evidence]
        return out


def _validate_loopback_url(base_url: str, *, allow_remote: bool = False) -> str:
    value = str(base_url).rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LocalModelEndpointError("model server URL must be http(s) with a hostname")
    host = parsed.hostname.lower()
    if not allow_remote and host not in {"127.0.0.1", "localhost", "::1"}:
        raise LocalModelEndpointError(
            "remote model endpoint refused; Sovereign Twin defaults to loopback-only serving"
        )
    return value


class LmStudioClient:
    """Small stdlib-only client for LM Studio / llmster local APIs."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        timeout: float = 180.0,
        allow_remote: bool = False,
    ):
        self.base_url = _validate_loopback_url(base_url, allow_remote=allow_remote)
        self.timeout = float(timeout)

    def _request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        req = Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urlopen(req, timeout=self.timeout) as response:  # noqa: S310 - loopback validated
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise LocalModelEndpointError(
                f"LM Studio/llmster request failed: {type(exc).__name__}: {exc}"
            ) from exc

    def models(self) -> list[dict[str, Any]]:
        data = self._request("GET", "/api/v0/models")
        rows = data.get("data") if isinstance(data, Mapping) else None
        if not isinstance(rows, list):
            raise LocalModelEndpointError("unexpected LM Studio models response")
        return [dict(row) for row in rows if isinstance(row, Mapping)]

    def chat(
        self,
        *,
        model: str,
        messages: Sequence[Mapping[str, str]],
        ttl_seconds: int,
        max_tokens: int,
        temperature: float,
    ) -> str:
        payload = {
            "model": model,
            "messages": [dict(row) for row in messages],
            "ttl": int(ttl_seconds),
            "max_tokens": int(max_tokens),
            "temperature": float(temperature),
            "stream": False,
        }
        data = self._request("POST", "/v1/chat/completions", payload)
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LocalModelEndpointError("unexpected LM Studio chat response") from exc
        if not isinstance(text, str):
            raise LocalModelEndpointError("LM Studio chat content must be text")
        return text


class SovereignTwinRuntime:
    """Read-only personal-context runtime over ContinuityOS memory + local Qwen."""

    def __init__(
        self,
        memory_db: str,
        *,
        client: LmStudioClient | None = None,
        recall_k: int = 8,
        profiles: Mapping[str, LocalModelProfile] | None = None,
    ):
        self.memory = Memory(memory_db, read_only=True)
        self.client = client or LmStudioClient()
        self.recall_k = int(recall_k)
        self.profiles = dict(profiles or DEFAULT_PROFILES)

    def close(self) -> None:
        store = self.memory.store
        close = getattr(store, "close", None)
        if callable(close):
            close()
            return
        connection = getattr(store, "con", None)
        connection_close = getattr(connection, "close", None)
        if callable(connection_close):
            connection_close()

    def evidence(self, query: str) -> tuple[TwinEvidence, ...]:
        hits = self.memory.recall(query, k=self.recall_k, current_only=True)
        return tuple(
            TwinEvidence(
                id=int(hit.id),
                namespace=str(hit.namespace),
                text=str(hit.text),
                score=float(hit.score),
                why=str(hit.why),
            )
            for hit in hits
        )

    @staticmethod
    def _system_prompt(evidence: Sequence[TwinEvidence]) -> str:
        rows = [
            {
                "ref": f"mem:{row.id}",
                "namespace": row.namespace,
                "text": row.text,
                "score": round(row.score, 4),
            }
            for row in evidence
        ]
        return (
            "You are Sovereign Twin in LOCAL SHADOW mode. "
            "Use the supplied ContinuityOS memory evidence when relevant. "
            "Never invent personal facts. Distinguish memory-backed statements from inference. "
            "Do not execute actions, place orders, send messages, modify files, or infer authority. "
            "If evidence is insufficient, say so. Cite useful memory references as mem:<id>.\n\n"
            "MEMORY_EVIDENCE_JSON:\n" + json.dumps(rows, ensure_ascii=False, sort_keys=True)
        )

    def ask(self, query: str, *, mode: str = "fast") -> TwinAnswer:
        if mode not in self.profiles:
            raise ValueError(f"unknown Sovereign Twin mode: {mode}")
        profile = self.profiles[mode]
        evidence = self.evidence(query)
        text = self.client.chat(
            model=profile.model,
            messages=(
                {"role": "system", "content": self._system_prompt(evidence)},
                {"role": "user", "content": str(query)},
            ),
            ttl_seconds=profile.ttl_seconds,
            max_tokens=profile.max_tokens,
            temperature=profile.temperature,
        )
        return TwinAnswer(text=text, model=profile.model, mode=mode, evidence=evidence)

    def doctor(self) -> dict[str, Any]:
        models = self.client.models()
        available = {str(row.get("id")) for row in models}
        profiles = {
            name: {**asdict(profile), "visible_to_server": profile.model in available}
            for name, profile in self.profiles.items()
        }
        return {
            "ok": all(row["visible_to_server"] for row in profiles.values()),
            "server": self.client.base_url,
            "profiles": profiles,
            "model_count": len(models),
            "execution_authority": EXECUTION_AUTHORITY,
            "can_execute": False,
        }
