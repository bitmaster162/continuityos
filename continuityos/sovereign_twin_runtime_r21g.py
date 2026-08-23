"""R21G Sovereign Twin runtime overlay: FAST chat-coupled streaming JIT acquisition.

R21F is retained byte-exact in sovereign_twin_runtime_r21f.py. Native DEEP remains
R21E behavior through the retained R21F lineage. R21G changes only the production
cold FAST path: exactly one streaming /api/v1/chat transaction owns JIT loading,
exact acquisition evidence, inference, and final instance identity. No explicit
FAST /api/v1/models/load request is issued by the R21G cold production path.

Warm FAST remains the inherited resident-chat behavior. If a custom/legacy client
does not implement the R21G FAST streaming method, inherited R21F behavior remains
available for compatibility.
"""
from __future__ import annotations

import json
from time import perf_counter as _system_perf_counter, sleep as _system_sleep
from typing import Any, Callable, Mapping
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from . import sovereign_twin_runtime_r21f as _r21f
from .sovereign_twin_runtime_r21f import *  # noqa: F401,F403

# Preserve complete R21F import surface, including underscore-prefixed helpers.
for _legacy_name, _legacy_value in vars(_r21f).items():
    if not _legacy_name.startswith("__"):
        globals().setdefault(_legacy_name, _legacy_value)
del _legacy_name, _legacy_value

# Preserve timing / transport monkeypatch semantics across retained overlays.
perf_counter = _system_perf_counter
sleep = _system_sleep
_r21f.perf_counter = lambda: perf_counter()
_r21f.sleep = lambda seconds: sleep(seconds)
_r21f.urlopen = lambda *args, **kwargs: urlopen(*args, **kwargs)

FAST_STREAM_RESIDENCY_RECONCILIATION_TIMEOUT_SECONDS = 10.0
FAST_STREAM_RESIDENCY_RECONCILIATION_POLL_SECONDS = 0.25


def _is_fast_inference_phase_event(event_type: str) -> bool:
    return event_type == "chat.end" or event_type.startswith(
        (
            "prompt_processing.",
            "reasoning.",
            "message.",
            "tool_call.",
            "tool.",
        )
    )


class LmStudioClient(_r21f.LmStudioClient):
    """R21F-compatible client plus R21G cold-FAST streaming JIT transport."""

    def chat_fast_streaming_jit_reconciled(
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
        """Run one FAST SSE chat; reconcile exact residency inside the same transaction."""
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
                    f"LM Studio FAST SSE event contained invalid JSON: {exc}"
                ) from exc
            if not isinstance(event_data, Mapping):
                raise LocalModelEndpointError("LM Studio FAST SSE event data must be an object")

            event_type = str(event_data.get("type") or event_name or "")
            if not event_type:
                raise LocalModelEndpointError("LM Studio FAST SSE event type is missing")
            event_types.append(event_type)

            if event_type == "chat.start":
                value = event_data.get("model_instance_id")
                if not isinstance(value, str) or not value:
                    raise LocalModelEndpointError(
                        "LM Studio FAST chat.start missing model_instance_id"
                    )
                if chat_start_id is not None and chat_start_id != value:
                    raise LocalModelEndpointError(
                        "LM Studio FAST chat.start model_instance_id changed within one stream"
                    )
                if model_load_end_id is not None and model_load_end_id != value:
                    raise LocalModelEndpointError(
                        "LM Studio FAST chat.start instance mismatch after model_load.end: "
                        f"load_end={model_load_end_id} chat_start={value}"
                    )
                chat_start_id = value
                return

            if event_type == "model_load.end":
                if model_load_end_id is not None:
                    raise LocalModelEndpointError(
                        "LM Studio emitted multiple model_load.end events for one FAST chat"
                    )
                value = event_data.get("model_instance_id")
                if not isinstance(value, str) or not value:
                    raise LocalModelEndpointError(
                        "LM Studio FAST model_load.end missing model_instance_id"
                    )
                if chat_start_id is not None and chat_start_id != value:
                    raise LocalModelEndpointError(
                        "LM Studio FAST model_load.end instance mismatch: "
                        f"chat_start={chat_start_id} load_end={value}"
                    )
                if reconciled_id is not None and reconciled_id != value:
                    raise LocalModelEndpointError(
                        "LM Studio FAST late model_load.end instance mismatch after residency "
                        f"reconciliation: reconciled={reconciled_id} load_end={value}"
                    )
                try:
                    load_seconds = float(event_data.get("load_time_seconds"))
                except (TypeError, ValueError) as exc:
                    raise LocalModelEndpointError(
                        "LM Studio FAST model_load.end missing numeric load_time_seconds"
                    ) from exc
                if load_seconds < 0:
                    raise LocalModelEndpointError(
                        "LM Studio FAST model_load.end load_time_seconds must be non-negative"
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
                and _is_fast_inference_phase_event(event_type)
                and on_residency_reconcile is not None
            ):
                if chat_start_id is None:
                    raise LocalModelEndpointError(
                        "LM Studio FAST inference-phase event arrived before chat.start"
                    )
                proven = on_residency_reconcile(chat_start_id, event_type)
                if not isinstance(proven, str) or not proven:
                    raise LocalModelEndpointError(
                        "FAST stream residency reconciliation returned an empty instance id"
                    )
                if proven != chat_start_id:
                    raise LocalModelEndpointError(
                        "FAST stream residency reconciliation instance mismatch: "
                        f"chat_start={chat_start_id} proven={proven}"
                    )
                reconciled_id = proven
                reconciliation_event_type = event_type
                acquisition_signal = "inference_event_residency"

            if event_type == "chat.end":
                result = event_data.get("result")
                if not isinstance(result, Mapping):
                    raise LocalModelEndpointError(
                        "LM Studio FAST chat.end missing result object"
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
            detail = _http_error_detail(exc)
            suffix = f": {detail}" if detail else ""
            raise LocalModelEndpointError(
                "LM Studio/llmster FAST streaming chat failed: "
                f"HTTPError: HTTP Error {exc.code}: {exc.reason}{suffix}"
            ) from exc
        except Exception as exc:
            raise LocalModelEndpointError(
                f"LM Studio/llmster FAST streaming chat failed: {type(exc).__name__}: {exc}"
            ) from exc

        if chat_start_id is None:
            raise LocalModelEndpointError("LM Studio FAST streaming chat emitted no chat.start")
        if chat_end_result is None:
            raise LocalModelEndpointError(
                "LM Studio FAST streaming chat emitted no chat.end",
                model_instance_id=model_load_end_id or reconciled_id or chat_start_id,
            )
        if stream_errors:
            raise LocalModelEndpointError(
                "LM Studio FAST streaming chat emitted error event(s): "
                + "; ".join(stream_errors),
                model_instance_id=model_load_end_id or reconciled_id or chat_start_id,
            )

        authoritative_id = model_load_end_id or reconciled_id
        if authoritative_id is None:
            raise LocalModelEndpointError(
                "LM Studio FAST streaming chat produced no exact acquisition proof; "
                "model_load.end absent and residency reconciliation unavailable",
                model_instance_id=chat_start_id,
            )

        result = self._chat_result_from_payload(chat_end_result)
        if result.model_instance_id != authoritative_id:
            raise LocalModelEndpointError(
                "LM Studio FAST chat.end instance mismatch: "
                f"acquired={authoritative_id} chat_end={result.model_instance_id}",
                model_instance_id=result.model_instance_id,
                stats=result.stats,
            )
        if chat_start_id != authoritative_id:
            raise LocalModelEndpointError(
                "LM Studio FAST chat.start instance mismatch: "
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


class SovereignTwinRuntime(_r21f.SovereignTwinRuntime):
    """R21G runtime: cold FAST uses one chat-coupled streaming JIT transaction."""

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

    def _wait_for_fast_stream_residency(
        self,
        profile: LocalModelProfile,
        *,
        expected_id: str,
    ) -> str:
        """Bounded read-only proof of exactly one FAST@ctx matching chat.start identity."""
        deadline = perf_counter() + FAST_STREAM_RESIDENCY_RECONCILIATION_TIMEOUT_SECONDS
        last_endpoint_error: LocalModelEndpointError | None = None
        while True:
            try:
                proven_id = self._probe_exact_fast_residency(
                    profile,
                    expected_id=expected_id,
                )
            except _FastResidencyUnsafeError:
                raise
            except LocalModelEndpointError as exc:
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
                    "FAST stream residency reconciliation did not prove exact chat.start "
                    "instance before bounded deadline" + detail
                )
            sleep(min(FAST_STREAM_RESIDENCY_RECONCILIATION_POLL_SECONDS, remaining))

    def _ask_fast_cold_streaming(
        self,
        query: str,
        *,
        profile: LocalModelProfile,
        evidence: Any,
    ) -> TwinAnswer:
        stream_chat = getattr(
            self.client,
            "chat_fast_streaming_jit_reconciled",
            None,
        )
        if not callable(stream_chat):
            # Compatibility only for custom/legacy clients. Production R21G client
            # always exposes the dedicated FAST streaming method.
            return super().ask(query, mode="fast")

        acquired_id: str | None = None
        acquisition_signal: str | None = None
        acquisition_event_type: str | None = None
        server_load_seconds: float | None = None

        def mark_acquired(instance_id: str, *, signal: str, event_type: str) -> str:
            nonlocal acquired_id, acquisition_signal, acquisition_event_type
            if acquired_id is not None:
                if acquired_id != instance_id:
                    raise LocalModelEndpointError(
                        "FAST acquisition identity changed within one stream: "
                        f"acquired={acquired_id} observed={instance_id}"
                    )
                return acquired_id

            if signal == "model_load.end":
                proven_id = self._probe_exact_fast_residency(
                    profile,
                    expected_id=instance_id,
                )
                if proven_id is None:
                    raise LocalModelEndpointError(
                        "FAST model_load.end was emitted but exact resident instance is absent"
                    )
            else:
                proven_id = self._wait_for_fast_stream_residency(
                    profile,
                    expected_id=instance_id,
                )
            acquired_id = proven_id
            acquisition_signal = signal
            acquisition_event_type = event_type
            return acquired_id

        def on_model_load_end(instance_id: str, load_time_seconds: float) -> None:
            nonlocal server_load_seconds
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

        authoritative_id = str(metadata.get("model_instance_id") or "")
        if not acquired_id or authoritative_id != acquired_id:
            raise LocalModelEndpointError(
                "FAST streaming acquisition metadata mismatch: "
                f"acquired={acquired_id} metadata={authoritative_id}"
            )

        final_id = self._probe_exact_fast_residency(
            profile,
            expected_id=acquired_id,
        )
        if final_id is None:
            raise LocalModelEndpointError(
                "FAST streaming chat completed but exact resident instance is absent"
            )

        stats = dict(result.stats)
        stats.update(
            {
                "fast_acquisition_signal": (
                    metadata.get("acquisition_signal") or acquisition_signal
                ),
                "fast_acquisition_event_type": (
                    metadata.get("acquisition_event_type") or acquisition_event_type
                ),
                "fast_model_load_end_seen": bool(metadata.get("model_load_end_seen")),
                "fast_jit_load_time_seconds": (
                    metadata.get("model_load_time_seconds")
                    if metadata.get("model_load_time_seconds") is not None
                    else server_load_seconds
                ),
                "fast_jit_stream_event_types": list(metadata.get("event_types") or ()),
            }
        )
        return TwinAnswer(
            text=result.text,
            model=profile.model,
            mode="fast",
            evidence=tuple(evidence),
            stats=stats,
            reasoning_present=result.reasoning is not None,
        )

    def ask(self, query: str, *, mode: str = "fast") -> TwinAnswer:
        if mode != "fast":
            return super().ask(query, mode=mode)

        with self._model_lock:
            if mode not in self.profiles:
                raise ValueError(f"unknown Sovereign Twin mode: {mode}")
            profile = self.profiles[mode]

            existing_id = self._probe_exact_fast_residency(profile)
            if existing_id is not None:
                # Preserve inherited warm-FAST behavior unchanged.
                return super().ask(query, mode=mode)

            stream_chat = getattr(
                self.client,
                "chat_fast_streaming_jit_reconciled",
                None,
            )
            if not callable(stream_chat):
                # Preserve legacy/custom-client compatibility.
                return super().ask(query, mode=mode)

            evidence = self.evidence(query)
            return self._ask_fast_cold_streaming(
                query,
                profile=profile,
                evidence=evidence,
            )
