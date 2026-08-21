"""Local-only Sovereign Twin runtime for LM Studio / llmster.

Product/runtime bridge only. This module is not the R13 scientific evaluator.
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
DEFAULT_EMBEDDING_MODEL = os.environ.get(
    "SOVEREIGN_TWIN_EMBEDDING_MODEL",
    "text-embedding-nomic-embed-text-v1.5",
)
NOMIC_DOCUMENT_TASK = "search_document"
NOMIC_QUERY_TASK = "search_query"


class LocalModelEndpointError(RuntimeError):
    """Raised when the model endpoint is unavailable or violates local-only policy."""

    def __init__(
        self,
        message: str,
        *,
        model_instance_id: str | None = None,
        stats: Mapping[str, Any] | None = None,
        output_types: Sequence[str] | None = None,
    ):
        super().__init__(message)
        self.model_instance_id = model_instance_id
        self.stats = dict(stats or {})
        self.output_types = tuple(output_types or ())


@dataclass(frozen=True)
class LocalModelProfile:
    model: str
    context_length: int
    reasoning: str
    max_output_tokens: int
    temperature: float
    unload_after_answer: bool = False
    expected_parallel: int = 1


DEFAULT_PROFILES: dict[str, LocalModelProfile] = {
    "fast": LocalModelProfile(
        model=os.environ.get("SOVEREIGN_TWIN_FAST_MODEL", "qwen3.5-4b"),
        context_length=8192,
        reasoning="off",
        max_output_tokens=1200,
        temperature=0.2,
        unload_after_answer=False,
    ),
    "deep": LocalModelProfile(
        model=os.environ.get("SOVEREIGN_TWIN_DEEP_MODEL", "qwen3.6-35b-a3b"),
        context_length=4096,
        reasoning="on",
        max_output_tokens=2200,
        temperature=0.15,
        unload_after_answer=True,
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
class LocalChatResult:
    text: str
    model_instance_id: str | None
    stats: Mapping[str, Any]
    reasoning: str | None = None


@dataclass(frozen=True)
class TwinAnswer:
    text: str
    model: str
    mode: str
    evidence: tuple[TwinEvidence, ...]
    stats: Mapping[str, Any]
    reasoning_present: bool
    execution_authority: str = EXECUTION_AUTHORITY
    can_execute: bool = False

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["evidence"] = [asdict(row) for row in self.evidence]
        out["stats"] = dict(self.stats)
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


def _task_prefixed_text(text: str, task: str | None) -> str:
    value = str(text).replace("\n", " ")
    if task is None:
        return value
    if task not in {NOMIC_DOCUMENT_TASK, NOMIC_QUERY_TASK}:
        raise ValueError(f"unsupported embedding task: {task}")
    prefix = task + ":"
    if value.lstrip().startswith(prefix):
        return value
    return f"{prefix} {value}"


class LmStudioClient:
    """Small stdlib-only client for LM Studio / llmster local APIs."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        timeout: float = 300.0,
        load_timeout: float = 600.0,
        allow_remote: bool = False,
    ):
        self.base_url = _validate_loopback_url(base_url, allow_remote=allow_remote)
        self.timeout = float(timeout)
        self.load_timeout = float(load_timeout)

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        req = Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        request_timeout = self.timeout if timeout is None else float(timeout)
        try:
            with urlopen(req, timeout=request_timeout) as response:  # noqa: S310 - loopback validated
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise LocalModelEndpointError(
                f"LM Studio/llmster request failed: {type(exc).__name__}: {exc}"
            ) from exc

    def models(self) -> list[dict[str, Any]]:
        data = self._request("GET", "/api/v1/models")
        rows = data.get("models") if isinstance(data, Mapping) else None
        if not isinstance(rows, list):
            raise LocalModelEndpointError("unexpected LM Studio v1 models response")
        return [dict(row) for row in rows if isinstance(row, Mapping)]

    def load(self, *, model: str, context_length: int) -> str:
        try:
            data = self._request(
                "POST",
                "/api/v1/models/load",
                {
                    "model": str(model),
                    "context_length": int(context_length),
                    "echo_load_config": True,
                },
                timeout=self.load_timeout,
            )
        except LocalModelEndpointError as exc:
            raise LocalModelEndpointError(
                f"LM Studio model load failed with load_timeout={self.load_timeout:g}s: {exc}"
            ) from exc
        if not isinstance(data, Mapping) or data.get("status") != "loaded":
            raise LocalModelEndpointError("LM Studio model load did not report status=loaded")
        instance_id_raw = data.get("instance_id")
        if not isinstance(instance_id_raw, str) or not instance_id_raw:
            # Older v1 beta builds used model_instance_id before the field was renamed.
            instance_id_raw = data.get("model_instance_id")
        if not isinstance(instance_id_raw, str) or not instance_id_raw:
            raise LocalModelEndpointError("LM Studio model load response missing instance_id")
        load_config = data.get("load_config")
        if not isinstance(load_config, Mapping):
            raise LocalModelEndpointError("LM Studio model load response missing load_config")
        try:
            loaded_context = int(load_config.get("context_length"))
        except (TypeError, ValueError) as exc:
            raise LocalModelEndpointError(
                "LM Studio model load response missing numeric context_length"
            ) from exc
        if loaded_context != int(context_length):
            raise LocalModelEndpointError(
                "LM Studio model load context_length mismatch: "
                f"expected={int(context_length)} actual={loaded_context}"
            )
        return instance_id_raw

    def unload(self, instance_id: str) -> None:
        if not instance_id:
            return
        self._request("POST", "/api/v1/models/unload", {"instance_id": str(instance_id)})

    def embed(
        self,
        text: str,
        *,
        model: str = DEFAULT_EMBEDDING_MODEL,
        task: str | None = None,
    ) -> list[float]:
        data = self._request(
            "POST",
            "/v1/embeddings",
            {"model": str(model), "input": _task_prefixed_text(text, task)},
        )
        rows = data.get("data") if isinstance(data, Mapping) else None
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], Mapping):
            raise LocalModelEndpointError("unexpected LM Studio embeddings response")
        vector = rows[0].get("embedding")
        if not isinstance(vector, list) or not vector:
            raise LocalModelEndpointError("LM Studio embedding vector missing")
        try:
            return [float(value) for value in vector]
        except (TypeError, ValueError) as exc:
            raise LocalModelEndpointError("LM Studio embedding vector must be numeric") from exc

    def chat(
        self,
        *,
        model: str,
        system_prompt: str,
        input_text: str,
        context_length: int,
        reasoning: str,
        max_output_tokens: int,
        temperature: float,
    ) -> LocalChatResult:
        payload = {
            "model": model,
            "input": str(input_text),
            "system_prompt": str(system_prompt),
            "context_length": int(context_length),
            "reasoning": str(reasoning),
            "max_output_tokens": int(max_output_tokens),
            "temperature": float(temperature),
            "stream": False,
            "store": False,
        }
        data = self._request("POST", "/api/v1/chat", payload)
        if not isinstance(data, Mapping):
            raise LocalModelEndpointError("unexpected LM Studio v1 chat response")

        model_instance_id = (
            str(data["model_instance_id"])
            if isinstance(data.get("model_instance_id"), str)
            else None
        )
        stats_raw = data.get("stats")
        stats = dict(stats_raw) if isinstance(stats_raw, Mapping) else {}
        output = data.get("output")
        if not isinstance(output, list):
            raise LocalModelEndpointError(
                "LM Studio v1 chat output must be a list",
                model_instance_id=model_instance_id,
                stats=stats,
            )
        messages: list[str] = []
        reasoning_rows: list[str] = []
        output_types: list[str] = []
        for row in output:
            if not isinstance(row, Mapping):
                continue
            row_type = str(row.get("type") or "")
            if row_type:
                output_types.append(row_type)
            content = row.get("content")
            if not isinstance(content, str):
                continue
            if row_type == "message":
                messages.append(content)
            elif row_type == "reasoning":
                reasoning_rows.append(content)

        text = "\n".join(x for x in messages if x).strip()
        if not text:
            total = stats.get("total_output_tokens")
            reasoning_tokens = stats.get("reasoning_output_tokens")
            diagnostic = (
                "LM Studio v1 chat returned no text message; "
                f"output_types={output_types or ['<none>']}; "
                f"total_output_tokens={total}; reasoning_output_tokens={reasoning_tokens}"
            )
            raise LocalModelEndpointError(
                diagnostic,
                model_instance_id=model_instance_id,
                stats=stats,
                output_types=output_types,
            )

        return LocalChatResult(
            text=text,
            model_instance_id=model_instance_id,
            stats=stats,
            reasoning="\n".join(reasoning_rows).strip() or None,
        )


class SovereignTwinRuntime:
    """Read-only personal-context runtime over ContinuityOS memory + local Qwen."""

    def __init__(
        self,
        memory_db: str,
        *,
        client: LmStudioClient | None = None,
        recall_k: int = 8,
        profiles: Mapping[str, LocalModelProfile] | None = None,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    ):
        self.client = client or LmStudioClient()
        self.embedding_model = str(embedding_model)
        self.memory_db = os.path.realpath(
            os.path.abspath(os.path.expanduser(str(memory_db)))
        )
        self.memory = Memory(
            self.memory_db,
            embedder=lambda text: self.client.embed(
                text,
                model=self.embedding_model,
                task=NOMIC_QUERY_TASK,
            ),
            read_only=True,
        )
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

    def _loaded_instances(self, model_key: str) -> list[Mapping[str, Any]]:
        rows = self.client.models()
        for row in rows:
            if str(row.get("key")) != str(model_key):
                continue
            instances = row.get("loaded_instances")
            if not isinstance(instances, list):
                return []
            return [instance for instance in instances if isinstance(instance, Mapping)]
        return []

    def _loaded_instance_ids(self, model_key: str) -> list[str]:
        ids: list[str] = []
        for instance in self._loaded_instances(model_key):
            value = instance.get("id")
            if isinstance(value, str) and value:
                ids.append(value)
        return ids

    def _ensure_fast_loaded(self, profile: LocalModelProfile) -> str:
        instances = self._loaded_instances(profile.model)
        if instances:
            first = instances[0]
            config = first.get("config")
            if not isinstance(config, Mapping):
                raise LocalModelEndpointError("loaded FAST model instance is missing config")
            try:
                loaded_context = int(config.get("context_length"))
            except (TypeError, ValueError) as exc:
                raise LocalModelEndpointError(
                    "loaded FAST model has invalid context_length"
                ) from exc
            if loaded_context != profile.context_length:
                raise LocalModelEndpointError(
                    "loaded FAST model context_length mismatch: "
                    f"expected={profile.context_length} actual={loaded_context}"
                )
            value = first.get("id")
            if isinstance(value, str) and value:
                return value
            raise LocalModelEndpointError("loaded FAST model instance is missing id")
        load = getattr(self.client, "load", None)
        if not callable(load):
            raise LocalModelEndpointError("FAST model is not loaded and client cannot load it")
        return str(load(model=profile.model, context_length=profile.context_length))

    def ask(self, query: str, *, mode: str = "fast") -> TwinAnswer:
        if mode not in self.profiles:
            raise ValueError(f"unknown Sovereign Twin mode: {mode}")
        profile = self.profiles[mode]
        evidence = self.evidence(query)
        if mode == "fast":
            self._ensure_fast_loaded(profile)
        result: LocalChatResult | None = None
        error_cleanup_ids: list[str] = []
        try:
            result = self.client.chat(
                model=profile.model,
                system_prompt=self._system_prompt(evidence),
                input_text=str(query),
                context_length=profile.context_length,
                reasoning=profile.reasoning,
                max_output_tokens=profile.max_output_tokens,
                temperature=profile.temperature,
            )
            return TwinAnswer(
                text=result.text,
                model=profile.model,
                mode=mode,
                evidence=evidence,
                stats=result.stats,
                reasoning_present=result.reasoning is not None,
            )
        except LocalModelEndpointError as exc:
            if profile.unload_after_answer:
                if exc.model_instance_id:
                    error_cleanup_ids = [exc.model_instance_id]
                else:
                    try:
                        error_cleanup_ids = self._loaded_instance_ids(profile.model)
                    except LocalModelEndpointError:
                        error_cleanup_ids = []
            raise
        finally:
            if not profile.unload_after_answer:
                pass
            elif result and result.model_instance_id:
                self.client.unload(result.model_instance_id)
            elif error_cleanup_ids:
                for instance_id in error_cleanup_ids:
                    try:
                        self.client.unload(instance_id)
                    except LocalModelEndpointError:
                        # Never mask the original inference failure with cleanup failure.
                        pass

    @staticmethod
    def _loaded_config(row: Mapping[str, Any]) -> Mapping[str, Any] | None:
        instances = row.get("loaded_instances")
        if not isinstance(instances, list) or not instances:
            return None
        first = instances[0]
        if not isinstance(first, Mapping):
            return None
        config = first.get("config")
        return dict(config) if isinstance(config, Mapping) else None

    def doctor(self) -> dict[str, Any]:
        models = self.client.models()
        by_key = {str(row.get("key")): row for row in models if row.get("key")}
        profiles: dict[str, dict[str, Any]] = {}
        for name, profile in self.profiles.items():
            row = by_key.get(profile.model)
            config = self._loaded_config(row or {})
            warnings: list[str] = []
            if config is not None:
                if int(config.get("context_length", -1)) != profile.context_length:
                    warnings.append("CONTEXT_LENGTH_MISMATCH")
                if int(config.get("parallel", profile.expected_parallel)) != profile.expected_parallel:
                    warnings.append("PARALLEL_NOT_1")
                if config.get("flash_attention") is False:
                    warnings.append("FLASH_ATTENTION_OFF")
                if config.get("offload_kv_cache_to_gpu") is False:
                    warnings.append("KV_CACHE_NOT_ON_GPU")
            profiles[name] = {
                **asdict(profile),
                "visible_to_server": row is not None,
                "loaded": config is not None,
                "loaded_config": dict(config) if config is not None else None,
                "warnings": warnings,
            }
        embedding_visible = self.embedding_model in by_key
        return {
            "ok": all(row["visible_to_server"] for row in profiles.values()) and embedding_visible,
            "server": self.client.base_url,
            "api": "lm-studio-rest-v1+openai-embeddings",
            "memory_db": self.memory_db,
            "profiles": profiles,
            "embedding": {
                "model": self.embedding_model,
                "visible_to_server": embedding_visible,
                "document_task_prefix": NOMIC_DOCUMENT_TASK,
                "query_task_prefix": NOMIC_QUERY_TASK,
            },
            "model_count": len(models),
            "execution_authority": EXECUTION_AUTHORITY,
            "can_execute": False,
        }
