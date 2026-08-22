"""R21E Sovereign Twin runtime overlay: stream-residency reconciliation for native DEEP.

R21D is retained byte-exact in sovereign_twin_runtime_r21d.py. Production native
DEEP still uses exactly one streaming /api/v1/chat transaction. R21E keeps the
R21D model_load.end path, but when that documented event is absent it may prove
the chat.start instance by bounded read-only catalog reconciliation at the first
inference-phase event. No second load/chat request is issued.
"""
from __future__ import annotations

import json
from time import perf_counter as _system_perf_counter, sleep as _system_sleep
from typing import Any, Callable, Mapping
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from . import sovereign_twin_runtime_r21d as _r21d
from .sovereign_twin_runtime_r21d import *  # noqa: F401,F403

# Preserve the complete R21D import surface, including underscore-prefixed helpers.
for _legacy_name, _legacy_value in vars(_r21d).items():
    if not _legacy_name.startswith("__"):
        globals().setdefault(_legacy_name, _legacy_value)
del _legacy_name, _legacy_value

# Keep timing/sleep monkeypatch semantics for inherited R21D/R21C compatibility paths.
perf_counter = _system_perf_counter
sleep = _system_sleep
_r21d.perf_counter = lambda: perf_counter()
_r21d.sleep = lambda seconds: sleep(seconds)
_r21d.urlopen = lambda *args, **kwargs: urlopen(*args, **kwargs)

DEEP_STREAM_RESIDENCY_RECONCILIATION_TIMEOUT_SECONDS = 10.0
DEEP_STREAM_RESIDENCY_RECONCILIATION_POLL_SECONDS = 0.25


def _is_inference_phase_event(event_type: str) -> bool:
    return event_type == "chat.end" or event_type.startswith(
        (
            "prompt_processing.",
            "reasoning.",
            "message.",
            "tool_call.",
            "tool.",
        )
    )


class LmStudioClient(_r21d.LmStudioClient):
    """R21D-compatible client plus fail-closed stream residency reconciliation."""

    def chat_streaming_jit_reconciled(
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
        on_residency_reconcile: Callable[[str, str], str] | None = None,
    ) -> tuple[LocalChatResult, dict[str, Any]]:
        """Run one SSE chat; reconcile exact residency if model_load.end is absent."""
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
        reconciled_id: str | None = None
        reconciliation_event_type: str | None = None
        acquisition_signal: str | None = None
        chat_end_result: Mapping[str, Any] | None = None
        event_types: list[str] = []
        stream_errors: list[str] = []

        def dispatch(event_name: str | None, data_lines: list[str]) -> None:
            nonlocal chat_start_id, model_load_end_id, model_load_time_seconds
            nonlocal reconciled_id, reconciliation_event_type, acquisition_signal
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
                if model_load_end_id is not None and model_load_end_id != value:
                    raise LocalModelEndpointError(
                        "LM Studio chat.start instance mismatch after model_load.end: "
                        f"load_end={model_load_end_id} chat_start={value}"
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
                if reconciled_id is not None and reconciled_id != value:
                    raise LocalModelEndpointError(
                        "LM Studio late model_load.end instance mismatch after residency reconciliation: "
                        f"reconciled={reconciled_id} load_end={value}"
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
                if acquisition_signal is None:
                    acquisition_signal = "model_load.end"
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

            if (
                model_load_end_id is None
                and reconciled_id is None
                and _is_inference_phase_event(event_type)
                and on_residency_reconcile is not None
            ):
                if chat_start_id is None:
                    raise LocalModelEndpointError(
                        "LM Studio inference-phase event arrived before chat.start; cannot reconcile DEEP"
                    )
                proven = on_residency_reconcile(chat_start_id, event_type)
                if not isinstance(proven, str) or not proven:
                    raise LocalModelEndpointError(
                        "DEEP stream residency reconciliation returned an empty instance id"
                    )
                if proven != chat_start_id:
                    raise LocalModelEndpointError(
                        "DEEP stream residency reconciliation instance mismatch: "
                        f"chat_start={chat_start_id} proven={proven}"
                    )
                reconciled_id = proven
                reconciliation_event_type = event_type
                acquisition_signal = "inference_event_residency"

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
            detail = _r21d._r21c._base._http_error_detail(exc)
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
        if chat_end_result is None:
            raise LocalModelEndpointError(
                "LM Studio streaming chat emitted no chat.end",
                model_instance_id=model_load_end_id or reconciled_id or chat_start_id,
            )
        if stream_errors:
            raise LocalModelEndpointError(
                "LM Studio streaming chat emitted error event(s): " + "; ".join(stream_errors),
                model_instance_id=model_load_end_id or reconciled_id or chat_start_id,
            )

        authoritative_id = model_load_end_id or reconciled_id
        if authoritative_id is None:
            raise LocalModelEndpointError(
                "LM Studio native DEEP streaming chat produced no exact acquisition proof; "
                "model_load.end absent and residency reconciliation unavailable",
                model_instance_id=chat_start_id,
            )

        result = self._chat_result_from_payload(chat_end_result)
        if result.model_instance_id != authoritative_id:
            raise LocalModelEndpointError(
                "LM Studio chat.end instance mismatch: "
                f"acquired={authoritative_id} chat_end={result.model_instance_id}",
                model_instance_id=result.model_instance_id,
                stats=result.stats,
            )
        if chat_start_id != authoritative_id:
            raise LocalModelEndpointError(
                "LM Studio chat.start instance mismatch: "
                f"chat_start={chat_start_id} acquired={authoritative_id}",
                model_instance_id=result.model_instance_id,
                stats=result.stats,
            )

        return result, {
            "model_instance_id": authoritative_id,
            "model_load_time_seconds": model_load_time_seconds,
            "model_load_end_seen": model_load_end_id is not None,
            "acquisition_signal": acquisition_signal,
            "acquisition_event_type": (
                "model_load.end"
                if acquisition_signal == "model_load.end"
                else reconciliation_event_type
            ),
            "event_types": tuple(event_types),
        }


class SovereignTwinRuntime(_r21d.SovereignTwinRuntime):
    """R21E runtime: R21D stream JIT plus exact residency reconciliation fallback."""

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

    def _wait_for_stream_residency(
        self,
        profile: LocalModelProfile,
        *,
        expected_id: str,
    ) -> str:
        """Bounded read-only proof of exactly one DEEP@ctx matching chat.start identity."""
        deadline = perf_counter() + DEEP_STREAM_RESIDENCY_RECONCILIATION_TIMEOUT_SECONDS
        last_endpoint_error: LocalModelEndpointError | None = None
        unsafe_cls = getattr(_r21d, "_DeepResidencyUnsafeError", None)
        while True:
            try:
                proven_id = self._probe_exact_deep_residency(
                    profile,
                    expected_id=expected_id,
                )
            except LocalModelEndpointError as exc:
                if unsafe_cls is not None and isinstance(exc, unsafe_cls):
                    raise
                last_endpoint_error = exc
            else:
                if proven_id is not None:
                    return proven_id

            remaining = deadline - perf_counter()
            if remaining <= 0:
                detail = (
                    f"; last residency read error={last_endpoint_error}"
                    if last_endpoint_error is not None
                    else ""
                )
                raise LocalModelEndpointError(
                    "DEEP stream residency reconciliation did not prove exact chat.start instance "
                    "before bounded deadline" + detail
                )
            sleep(min(DEEP_STREAM_RESIDENCY_RECONCILIATION_POLL_SECONDS, remaining))

    def _ask_deep(
        self,
        query: str,
        *,
        profile: LocalModelProfile,
        evidence: Any,
        phase_timings_ms: dict[str, float],
        request_started_at: float,
    ) -> TwinAnswer:
        """Use one streaming chat; reconcile exact residency if model_load.end is absent."""
        stream_chat = getattr(self.client, "chat_streaming_jit_reconciled", None)
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
        acquisition_signal: str | None = None
        acquisition_event_type: str | None = None
        model_load_end_seen = False

        def mark_acquired(instance_id: str, *, signal: str, event_type: str) -> str:
            nonlocal acquired_id, acquisition_completed_at
            nonlocal acquisition_signal, acquisition_event_type
            if acquired_id is not None:
                if acquired_id != instance_id:
                    raise LocalModelEndpointError(
                        "native DEEP acquisition identity changed within one stream: "
                        f"acquired={acquired_id} observed={instance_id}"
                    )
                return acquired_id

            phase_timings_ms["deep_load"] = self._elapsed_ms(stream_started)
            proof_started = perf_counter()
            if signal == "model_load.end":
                proven_id = self._probe_exact_deep_residency(
                    profile,
                    expected_id=instance_id,
                )
                if proven_id is None:
                    raise LocalModelEndpointError(
                        "DEEP model_load.end was emitted but exact resident instance is absent"
                    )
            else:
                proven_id = self._wait_for_stream_residency(
                    profile,
                    expected_id=instance_id,
                )
            acquired_id = proven_id
            phase_timings_ms["deep_acquisition_proof"] = self._elapsed_ms(proof_started)
            acquisition_completed_at = perf_counter()
            acquisition_signal = signal
            acquisition_event_type = event_type
            return proven_id

        def on_model_load_end(instance_id: str, load_time_seconds: float) -> None:
            nonlocal server_load_seconds, model_load_end_seen
            model_load_end_seen = True
            server_load_seconds = float(load_time_seconds)
            mark_acquired(
                instance_id,
                signal="model_load.end",
                event_type="model_load.end",
            )

        def on_residency_reconcile(instance_id: str, event_type: str) -> str:
            return mark_acquired(
                instance_id,
                signal="inference_event_residency",
                event_type=event_type,
            )

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
                on_residency_reconcile=on_residency_reconcile,
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
            meta_id = metadata.get("model_instance_id") if isinstance(metadata, Mapping) else None
            if isinstance(meta_id, str) and meta_id != acquired_id:
                raise LocalModelEndpointError(
                    "native DEEP streaming metadata instance mismatch: "
                    f"expected={acquired_id} actual={meta_id}"
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
        stats["deep_acquisition_signal"] = acquisition_signal
        stats["deep_acquisition_event_type"] = acquisition_event_type
        stats["deep_model_load_end_seen"] = bool(model_load_end_seen)
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
