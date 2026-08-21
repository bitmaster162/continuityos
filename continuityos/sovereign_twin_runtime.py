"""R21D Sovereign Twin runtime overlay: chat-coupled streaming JIT DEEP acquisition.

R21C is retained byte-exact in sovereign_twin_runtime_r21c.py. The production
LM Studio client changes native DEEP only: one streaming /api/v1/chat request
owns JIT load, readiness evidence, inference, and final instance identity.
"""
from __future__ import annotations

import json
from time import perf_counter as _system_perf_counter, sleep as _system_sleep
from typing import Any, Callable, Mapping
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from . import sovereign_twin_runtime_r21c as _r21c
from .sovereign_twin_runtime_r21c import *  # noqa: F401,F403

# Preserve the complete R21C import surface, including underscore-prefixed helpers.
for _legacy_name, _legacy_value in vars(_r21c).items():
    if not _legacy_name.startswith("__"):
        globals().setdefault(_legacy_name, _legacy_value)
del _legacy_name, _legacy_value

# Keep timing/sleep monkeypatch semantics for inherited R21C compatibility paths.
perf_counter = _system_perf_counter
sleep = _system_sleep
_r21c.perf_counter = lambda: perf_counter()
_r21c.sleep = lambda seconds: sleep(seconds)


def _looks_like_already_unloaded_error(exc: BaseException) -> bool:
    """Recognize only the exact idempotent-cleanup case observed from LM Studio."""
    value = str(exc).lower()
    return "http error 404" in value and "not loaded" in value


class LmStudioClient(_r21c.LmStudioClient):
    """R21C-compatible client plus R21D chat-coupled streaming JIT acquisition."""

    @staticmethod
    def _chat_result_from_payload(data: Mapping[str, Any]) -> LocalChatResult:
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
                "LM Studio v1 streaming chat output must be a list",
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

        text = "\n".join(value for value in messages if value).strip()
        if not text:
            total = stats.get("total_output_tokens")
            reasoning_tokens = stats.get("reasoning_output_tokens")
            raise LocalModelEndpointError(
                "LM Studio v1 streaming chat returned no text message; "
                f"output_types={output_types or ['<none>']}; "
                f"total_output_tokens={total}; reasoning_output_tokens={reasoning_tokens}",
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

    def chat_streaming_jit(
        self,
        *,
        model: str,
        system_prompt: str,
        input_text: str,
        context_length: int,
        reasoning: str,
        max_output_tokens: int,
        temperature: float,
        on_model_load_end: Callable[[str, float], None] | None = None,
    ) -> tuple[LocalChatResult, dict[str, Any]]:
        """Run one SSE chat transaction and bind JIT load completion to the same instance."""
        payload = {
            "model": str(model),
            "input": str(input_text),
            "system_prompt": str(system_prompt),
            "context_length": int(context_length),
            "reasoning": str(reasoning),
            "max_output_tokens": int(max_output_tokens),
            "temperature": float(temperature),
            "stream": True,
            "store": False,
        }
        req = Request(
            self.base_url + "/api/v1/chat",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
        )

        chat_start_id: str | None = None
        model_load_end_id: str | None = None
        model_load_time_seconds: float | None = None
        chat_end_result: Mapping[str, Any] | None = None
        event_types: list[str] = []
        stream_errors: list[str] = []

        def dispatch(event_name: str | None, data_lines: list[str]) -> None:
            nonlocal chat_start_id, model_load_end_id, model_load_time_seconds
            nonlocal chat_end_result
            if not data_lines:
                return
            try:
                event_data = json.loads("\n".join(data_lines))
            except Exception as exc:
                raise LocalModelEndpointError(
                    f"LM Studio SSE event contained invalid JSON: {exc}"
                ) from exc
            if not isinstance(event_data, Mapping):
                raise LocalModelEndpointError("LM Studio SSE event data must be an object")

            event_type = str(event_data.get("type") or event_name or "")
            if not event_type:
                raise LocalModelEndpointError("LM Studio SSE event type is missing")
            event_types.append(event_type)

            if event_type == "chat.start":
                value = event_data.get("model_instance_id")
                if not isinstance(value, str) or not value:
                    raise LocalModelEndpointError(
                        "LM Studio chat.start missing model_instance_id"
                    )
                if chat_start_id is not None and chat_start_id != value:
                    raise LocalModelEndpointError(
                        "LM Studio chat.start model_instance_id changed within one stream"
                    )
                chat_start_id = value
                return

            if event_type == "model_load.end":
                if model_load_end_id is not None:
                    raise LocalModelEndpointError(
                        "LM Studio emitted multiple model_load.end events for one native DEEP chat"
                    )
                value = event_data.get("model_instance_id")
                if not isinstance(value, str) or not value:
                    raise LocalModelEndpointError(
                        "LM Studio model_load.end missing model_instance_id"
                    )
                if chat_start_id is not None and chat_start_id != value:
                    raise LocalModelEndpointError(
                        "LM Studio model_load.end instance mismatch: "
                        f"chat_start={chat_start_id} load_end={value}"
                    )
                try:
                    load_seconds = float(event_data.get("load_time_seconds"))
                except (TypeError, ValueError) as exc:
                    raise LocalModelEndpointError(
                        "LM Studio model_load.end missing numeric load_time_seconds"
                    ) from exc
                if load_seconds < 0:
                    raise LocalModelEndpointError(
                        "LM Studio model_load.end load_time_seconds must be non-negative"
                    )
                if on_model_load_end is not None:
                    on_model_load_end(value, load_seconds)
                model_load_end_id = value
                model_load_time_seconds = load_seconds
                return

            if event_type == "error":
                error = event_data.get("error")
                if isinstance(error, Mapping):
                    kind = str(error.get("type") or "unknown")
                    message = str(error.get("message") or "stream error")
                    stream_errors.append(f"{kind}: {message}")
                else:
                    stream_errors.append("unknown: malformed error event")
                return

            if event_type == "chat.end":
                result = event_data.get("result")
                if not isinstance(result, Mapping):
                    raise LocalModelEndpointError(
                        "LM Studio chat.end missing result object"
                    )
                chat_end_result = result

        event_name: str | None = None
        data_lines: list[str] = []
        try:
            with urlopen(req, timeout=self.timeout) as response:  # noqa: S310 - loopback validated
                for raw_line in response:
                    line = raw_line.decode("utf-8").rstrip("\r\n")
                    if line == "":
                        dispatch(event_name, data_lines)
                        event_name = None
                        data_lines = []
                        continue
                    if line.startswith(":"):
                        continue
                    if line.startswith("event:"):
                        event_name = line[6:].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line[5:].lstrip())
                dispatch(event_name, data_lines)
        except LocalModelEndpointError:
            raise
        except HTTPError as exc:
            detail = _r21c._base._http_error_detail(exc)
            suffix = f": {detail}" if detail else ""
            raise LocalModelEndpointError(
                "LM Studio/llmster streaming chat failed: "
                f"HTTPError: HTTP Error {exc.code}: {exc.reason}{suffix}"
            ) from exc
        except Exception as exc:
            raise LocalModelEndpointError(
                f"LM Studio/llmster streaming chat failed: {type(exc).__name__}: {exc}"
            ) from exc

        if chat_start_id is None:
            raise LocalModelEndpointError("LM Studio streaming chat emitted no chat.start")
        if model_load_end_id is None:
            raise LocalModelEndpointError(
                "LM Studio native DEEP streaming chat emitted no model_load.end after cold pre-proof",
                model_instance_id=chat_start_id,
            )
        if chat_end_result is None:
            raise LocalModelEndpointError(
                "LM Studio streaming chat emitted no chat.end",
                model_instance_id=model_load_end_id,
            )
        if stream_errors:
            raise LocalModelEndpointError(
                "LM Studio streaming chat emitted error event(s): " + "; ".join(stream_errors),
                model_instance_id=model_load_end_id,
            )

        result = self._chat_result_from_payload(chat_end_result)
        if result.model_instance_id != model_load_end_id:
            raise LocalModelEndpointError(
                "LM Studio chat.end instance mismatch: "
                f"load_end={model_load_end_id} chat_end={result.model_instance_id}",
                model_instance_id=result.model_instance_id,
                stats=result.stats,
            )
        if chat_start_id != model_load_end_id:
            raise LocalModelEndpointError(
                "LM Studio chat.start instance mismatch: "
                f"chat_start={chat_start_id} load_end={model_load_end_id}",
                model_instance_id=result.model_instance_id,
                stats=result.stats,
            )
        assert model_load_time_seconds is not None
        return result, {
            "model_instance_id": model_load_end_id,
            "model_load_time_seconds": model_load_time_seconds,
            "event_types": tuple(event_types),
        }


class SovereignTwinRuntime(_r21c.SovereignTwinRuntime):
    """R21D runtime: streaming JIT native DEEP with R21C compatibility fallback."""

    def __init__(
        self,
        memory_db: str,
        *,
        client: LmStudioClient | None = None,
        recall_k: int = 8,
        profiles: Mapping[str, LocalModelProfile] | None = None,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    ):
        super().__init__(
            memory_db,
            client=client or LmStudioClient(),
            recall_k=recall_k,
            profiles=profiles,
            embedding_model=embedding_model,
        )

    def _release_deep_after_request(
        self,
        profile: LocalModelProfile,
        acquired_id: str,
    ) -> dict[str, float]:
        """Unload exact DEEP id; a 404 is success only when read-back proves absence."""
        phase_timings_ms: dict[str, float] = {}

        phase_started = perf_counter()
        try:
            self.client.unload(acquired_id)
        except LocalModelEndpointError as exc:
            if not _looks_like_already_unloaded_error(exc):
                try:
                    remaining = self._strict_loaded_instance_ids(profile.model, label="DEEP")
                except LocalModelEndpointError:
                    remaining = []
                self._cleanup_deep_ids_best_effort(remaining)
                raise LocalModelEndpointError(
                    f"DEEP exact unload failed after native DEEP: {exc}"
                ) from exc

            remaining = self._strict_loaded_instance_ids(profile.model, label="DEEP")
            if remaining:
                cleanup_failures = self._cleanup_deep_ids_best_effort(remaining)
                detail = (
                    f"; residual cleanup failures={cleanup_failures}"
                    if cleanup_failures
                    else ""
                )
                raise LocalModelEndpointError(
                    "DEEP unload returned already-absent 404 but configured DEEP remains resident; "
                    f"residual_ids={remaining}{detail}"
                ) from exc
        phase_timings_ms["deep_unload"] = self._elapsed_ms(phase_started)

        phase_started = perf_counter()
        remaining = self._strict_loaded_instance_ids(profile.model, label="DEEP")
        if remaining:
            cleanup_failures = self._cleanup_deep_ids_best_effort(remaining)
            detail = (
                f"; residual cleanup failures={cleanup_failures}"
                if cleanup_failures
                else ""
            )
            raise LocalModelEndpointError(
                "DEEP remains resident after exact unload; "
                f"residual_ids={remaining}{detail}"
            )
        phase_timings_ms["deep_post_unload_proof"] = self._elapsed_ms(phase_started)
        return phase_timings_ms

    def _ask_deep(
        self,
        query: str,
        *,
        profile: LocalModelProfile,
        evidence: Any,
        phase_timings_ms: dict[str, float],
        request_started_at: float,
    ) -> TwinAnswer:
        """Use one streaming chat transaction for native DEEP JIT load + inference."""
        stream_chat = getattr(self.client, "chat_streaming_jit", None)
        if not callable(stream_chat):
            return super()._ask_deep(
                query,
                profile=profile,
                evidence=evidence,
                phase_timings_ms=phase_timings_ms,
                request_started_at=request_started_at,
            )

        phase_started = perf_counter()
        existing = self._strict_loaded_instance_ids(profile.model, label="DEEP")
        phase_timings_ms["deep_pre_acquire_proof"] = self._elapsed_ms(phase_started)
        if existing:
            raise LocalModelEndpointError(
                "DEEP already resident before chat-coupled JIT acquisition; refusing native DEEP"
            )

        stream_started = perf_counter()
        acquired_id: str | None = None
        acquisition_completed_at: float | None = None
        server_load_seconds: float | None = None

        def on_model_load_end(instance_id: str, load_time_seconds: float) -> None:
            nonlocal acquired_id, acquisition_completed_at, server_load_seconds
            phase_timings_ms["deep_load"] = self._elapsed_ms(stream_started)
            proof_started = perf_counter()
            proven_id = self._probe_exact_deep_residency(
                profile,
                expected_id=instance_id,
            )
            if proven_id is None:
                raise LocalModelEndpointError(
                    "DEEP model_load.end was emitted but exact resident instance is absent"
                )
            acquired_id = proven_id
            server_load_seconds = float(load_time_seconds)
            phase_timings_ms["deep_acquisition_proof"] = self._elapsed_ms(proof_started)
            acquisition_completed_at = perf_counter()

        metadata: Mapping[str, Any] = {}
        try:
            result, metadata = stream_chat(
                model=profile.model,
                system_prompt=self._system_prompt(evidence),
                input_text=str(query),
                context_length=profile.context_length,
                reasoning=profile.reasoning,
                max_output_tokens=profile.max_output_tokens,
                temperature=profile.temperature,
                on_model_load_end=on_model_load_end,
            )
            if acquired_id is None or acquisition_completed_at is None:
                raise LocalModelEndpointError(
                    "native DEEP streaming chat completed without exact acquisition proof"
                )
            if result.model_instance_id != acquired_id:
                raise LocalModelEndpointError(
                    "native DEEP streaming chat instance mismatch: "
                    f"expected={acquired_id} actual={result.model_instance_id}"
                )
            phase_timings_ms["deep_chat"] = round(
                (perf_counter() - acquisition_completed_at) * 1000.0,
                3,
            )
        except Exception as exc:
            if acquired_id is not None:
                try:
                    self._release_deep_after_request(profile, acquired_id)
                except LocalModelEndpointError as cleanup_exc:
                    raise LocalModelEndpointError(
                        f"{exc}; DEEP cleanup failed: {cleanup_exc}"
                    ) from exc
            else:
                self._cleanup_failed_deep_acquisition(profile)
            raise

        release_timings = self._release_deep_after_request(profile, acquired_id)
        phase_timings_ms.update(release_timings)
        phase_timings_ms["total_request"] = self._elapsed_ms(request_started_at)

        stats = dict(result.stats)
        stats["deep_phase_timings_ms"] = dict(phase_timings_ms)
        if server_load_seconds is not None:
            stats["deep_jit_load_time_seconds"] = server_load_seconds
        event_types = metadata.get("event_types") if isinstance(metadata, Mapping) else None
        if isinstance(event_types, (list, tuple)):
            stats["deep_jit_stream_event_types"] = list(event_types)

        return TwinAnswer(
            text=result.text,
            model=profile.model,
            mode="deep",
            evidence=tuple(evidence),
            stats=stats,
            reasoning_present=result.reasoning is not None,
        )
