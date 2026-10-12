"""R21H Sovereign Twin runtime overlay: startup FAST streaming-JIT prewarm.

R21G is retained byte-exact in sovereign_twin_runtime_r21g.py. R21H keeps DEEP
behavior inherited from R21G, but hardens the official LM Studio FAST path around
embedding/model residency: cold startup proves embedding readiness before the
final FAST acquisition, and each FAST request retrieves evidence before its exact
FAST residency decision. If evidence embedding evicts FAST, R21H reacquires only
through the R21G chat-coupled streaming-JIT path; the historical explicit FAST
loader is never used by the R21H official production FAST path.

Custom/legacy clients that do not implement the R21G streaming transport retain
the inherited R21G/R21F compatibility path only when they expose the historical
``load`` contract. This compatibility escape hatch never applies to LmStudioClient
or its subclasses.
"""
from __future__ import annotations

from dataclasses import replace as _replace
from threading import get_ident as _get_ident
from typing import Any

from . import sovereign_twin_runtime_r21g as _r21g
from .person_twin_r21h_evidence import (
    PersonTwinEvidenceError,
    PersonTwinR21HEvidenceAdapter,
)
from .sovereign_twin_runtime_r21g import *  # noqa: F401,F403

for _legacy_name, _legacy_value in vars(_r21g).items():
    if not _legacy_name.startswith("__"):
        globals().setdefault(_legacy_name, _legacy_value)
del _legacy_name, _legacy_value

_r21g.perf_counter = lambda: perf_counter()
_r21g.sleep = lambda seconds: sleep(seconds)
_r21g.urlopen = lambda *args, **kwargs: urlopen(*args, **kwargs)

FAST_STARTUP_PREWARM_QUERY = (
    "Sovereign Twin startup prewarm only. Reply exactly FAST_PREWARM_OK."
)
EMBEDDING_STARTUP_READINESS_QUERY = (
    "Sovereign Twin startup embedding readiness."
)


class _PersonPromptBoundary:
    """Keep historical class-static formatting, guard protected instance calls."""

    def __get__(self, instance, owner):
        if instance is None:
            return _r21g.SovereignTwinRuntime._system_prompt
        return instance._person_system_prompt


class _PersonDeepBoundary:
    """Preserve inherited DEEP identity while denying protected instance entry."""

    def __get__(self, instance, owner):
        original = _r21g.SovereignTwinRuntime._ask_deep
        if instance is None:
            return original
        if getattr(instance, "_person_evidence_adapter", None) is None:
            return original.__get__(instance, owner)
        return instance._person_deep_denied


class SovereignTwinRuntime(_r21g.SovereignTwinRuntime):
    """R21G runtime plus fail-closed embedding-aware FAST startup/request ordering."""

    _system_prompt = _PersonPromptBoundary()
    _ask_deep = _PersonDeepBoundary()

    def __init__(
        self, memory_db: str, *, client: LmStudioClient | None = None,
        recall_k: int = 8, profiles: Mapping[str, LocalModelProfile] | None = None,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
        person_evidence_adapter: PersonTwinR21HEvidenceAdapter | None = None,
    ):
        if person_evidence_adapter is not None and type(person_evidence_adapter) is not PersonTwinR21HEvidenceAdapter:
            raise PersonTwinEvidenceError("PERSON_ADAPTER_CONFIGURATION_INVALID")
        super().__init__(memory_db, client=client, recall_k=recall_k,
                         profiles=profiles, embedding_model=embedding_model)
        self._person_evidence_adapter = person_evidence_adapter
        self._person_active_request = None

    def _person_request(self) -> dict[str, Any]:
        active = getattr(self, "_person_active_request", None)
        if active is None or active["owner_thread"] != _get_ident() or active["adapter"] is not getattr(self, "_person_evidence_adapter", None):
            raise PersonTwinEvidenceError("PERSON_ACTIVE_ASK_REQUIRED")
        return active

    def _person_deep_denied(self, *args: Any, **kwargs: Any) -> TwinAnswer:
        raise PersonTwinEvidenceError("PERSON_PROTECTED_DEEP_UNSUPPORTED")

    def evidence(self, query: str) -> tuple[TwinEvidence, ...]:
        adapter = getattr(self, "_person_evidence_adapter", None)
        if adapter is None:
            return super().evidence(query)
        with self._model_lock:
            active = self._person_request()
            if query != active["query"]:
                raise PersonTwinEvidenceError("PERSON_ACTIVE_QUERY_MISMATCH")
            evidence = adapter.prepare(query, self.memory.store)
            active["evidence"] = evidence
            return evidence

    def _person_system_prompt(self, evidence: Sequence[TwinEvidence]) -> str:
        adapter = getattr(self, "_person_evidence_adapter", None)
        if adapter is None:
            return super()._system_prompt(evidence)
        with self._model_lock:
            active = self._person_request()
            if evidence is not active["evidence"]:
                raise PersonTwinEvidenceError("PERSON_FOREIGN_PROMPT_EVIDENCE")
            active["receipt"] = adapter.validate_for_prompt(
                active["query"], self.memory.store, evidence,
            )
            return super()._system_prompt(evidence)

    def _ask_fast_cold_streaming(
        self, query: str, *, profile: LocalModelProfile, evidence: Any,
    ) -> TwinAnswer:
        if getattr(self, "_person_evidence_adapter", None) is None:
            return super()._ask_fast_cold_streaming(query, profile=profile, evidence=evidence)
        with self._model_lock:
            active = self._person_request()
            if query != active["query"] or evidence is not active["evidence"] or profile != self.profiles["fast"]:
                raise PersonTwinEvidenceError("PERSON_FOREIGN_STREAM_REQUEST")
            self._require_fast_streaming_transport()
            return super()._ask_fast_cold_streaming(query, profile=profile, evidence=evidence)

    def _require_fast_streaming_transport(self):
        stream_chat = getattr(
            self.client,
            "chat_fast_streaming_jit_reconciled",
            None,
        )
        if not callable(stream_chat):
            raise LocalModelEndpointError(
                "R21H FAST requires the R21G streaming-JIT transport; "
                "explicit-load compatibility fallback is forbidden"
            )
        return stream_chat

    def _uses_legacy_fast_client_compatibility(self) -> bool:
        """Return True only for a non-production client with the old load contract."""
        stream_chat = getattr(
            self.client,
            "chat_fast_streaming_jit_reconciled",
            None,
        )
        if callable(stream_chat):
            return False
        if isinstance(self.client, LmStudioClient):
            return False
        return callable(getattr(self.client, "load", None))

    def prewarm_fast_startup(self) -> dict[str, Any]:
        """Make exact FAST chat-ready before API bind without touching memory.

        Already-resident exact FAST remains a zero-call no-op. When FAST is cold,
        first prove the embedding endpoint with a fixed query that bypasses
        canonical memory, then make FAST the final startup acquisition.
        """
        if getattr(self, "_person_evidence_adapter", None) is not None:
            raise PersonTwinEvidenceError("PERSON_PROTECTED_PREWARM_UNSUPPORTED")
        with self._model_lock:
            profile = self.profiles["fast"]

            existing_id = self._probe_exact_fast_residency(profile)
            if existing_id is not None:
                return {
                    "ok": True,
                    "mode": "fast",
                    "model": profile.model,
                    "context_length": profile.context_length,
                    "model_instance_id": existing_id,
                    "already_resident": True,
                    "embedding_readiness_performed": False,
                    "embedding_dimensions": None,
                    "acquisition_signal": "already_resident",
                    "acquisition_event_type": "already_resident",
                    "model_load_end_seen": False,
                    "jit_load_time_seconds": None,
                    "stream_event_types": [],
                    "execution_authority": "NONE",
                    "can_execute": False,
                }

            embed = getattr(self.client, "embed", None)
            if not callable(embed):
                raise LocalModelEndpointError(
                    "R21H FAST startup prewarm requires embedding readiness "
                    "before final FAST acquisition"
                )
            vector = embed(
                EMBEDDING_STARTUP_READINESS_QUERY,
                model=self.embedding_model,
                task=NOMIC_QUERY_TASK,
            )
            if not isinstance(vector, list) or not vector:
                raise LocalModelEndpointError(
                    "R21H startup embedding readiness returned no vector"
                )

            existing_after_embedding = self._probe_exact_fast_residency(profile)
            if existing_after_embedding is not None:
                return {
                    "ok": True,
                    "mode": "fast",
                    "model": profile.model,
                    "context_length": profile.context_length,
                    "model_instance_id": existing_after_embedding,
                    "already_resident": True,
                    "embedding_readiness_performed": True,
                    "embedding_dimensions": len(vector),
                    "acquisition_signal": "resident_after_embedding_readiness",
                    "acquisition_event_type": "residency_probe",
                    "model_load_end_seen": False,
                    "jit_load_time_seconds": None,
                    "stream_event_types": [],
                    "execution_authority": "NONE",
                    "can_execute": False,
                }

            self._require_fast_streaming_transport()

            answer = self._ask_fast_cold_streaming(
                FAST_STARTUP_PREWARM_QUERY,
                profile=profile,
                evidence=(),
            )

            final_id = self._probe_exact_fast_residency(profile)
            if final_id is None:
                raise LocalModelEndpointError(
                    "R21H FAST startup prewarm completed without exact resident FAST"
                )

            stats = dict(answer.stats)
            return {
                "ok": True,
                "mode": "fast",
                "model": profile.model,
                "context_length": profile.context_length,
                "model_instance_id": final_id,
                "already_resident": False,
                "embedding_readiness_performed": True,
                "embedding_dimensions": len(vector),
                "acquisition_signal": stats.get("fast_acquisition_signal"),
                "acquisition_event_type": stats.get("fast_acquisition_event_type"),
                "model_load_end_seen": bool(stats.get("fast_model_load_end_seen")),
                "jit_load_time_seconds": stats.get("fast_jit_load_time_seconds"),
                "stream_event_types": list(
                    stats.get("fast_jit_stream_event_types") or ()
                ),
                "execution_authority": "NONE",
                "can_execute": False,
            }

    def ask(self, query: str, *, mode: str = "fast") -> TwinAnswer:
        adapter = getattr(self, "_person_evidence_adapter", None)
        if adapter is None:
            return self._ask_r21h(query, mode=mode)
        if mode != "fast" or not callable(getattr(self.client, "chat_fast_streaming_jit_reconciled", None)):
            raise PersonTwinEvidenceError("PERSON_PROTECTED_FAST_STREAMING_ONLY")
        with self._model_lock:
            if getattr(self, "_person_active_request", None) is not None:
                raise PersonTwinEvidenceError("PERSON_NESTED_ASK_DENIED")
            self._person_active_request = {
                "adapter": adapter, "query": query, "owner_thread": _get_ident(),
                "evidence": None, "receipt": None, "dispatcher_entered": False,
            }
            try:
                answer = self._ask_r21h(query, mode=mode)
                receipt = self._person_request()["receipt"]
                if receipt is None:
                    raise PersonTwinEvidenceError("PERSON_PROMPT_REVALIDATION_MISSING")
                return _replace(answer, stats={**answer.stats, "person_evidence": receipt})
            finally:
                self._person_active_request = None

    def _ask_r21h(self, query: str, *, mode: str = "fast") -> TwinAnswer:
        """Answer FAST after evidence/reprobe, preserving old custom-client fallback."""
        if getattr(self, "_person_evidence_adapter", None) is not None:
            with self._model_lock:
                active = self._person_request()
                if query != active["query"]:
                    raise PersonTwinEvidenceError("PERSON_ACTIVE_QUERY_MISMATCH")
                if mode != "fast" or not callable(getattr(self.client, "chat_fast_streaming_jit_reconciled", None)):
                    raise PersonTwinEvidenceError("PERSON_PROTECTED_FAST_STREAMING_ONLY")
                if active["dispatcher_entered"]:
                    raise PersonTwinEvidenceError("PERSON_NESTED_DISPATCH_DENIED")
                active["dispatcher_entered"] = True
        if mode != "fast":
            return super().ask(query, mode=mode)

        if self._uses_legacy_fast_client_compatibility():
            return super().ask(query, mode=mode)

        with self._model_lock:
            if mode not in self.profiles:
                raise ValueError(f"unknown Sovereign Twin mode: {mode}")
            profile = self.profiles[mode]

            evidence = self.evidence(query)
            resident_id = self._probe_exact_fast_residency(profile)

            if resident_id is None:
                self._require_fast_streaming_transport()
                return self._ask_fast_cold_streaming(
                    query,
                    profile=profile,
                    evidence=evidence,
                )

            result = self.client.chat(
                model=profile.model,
                system_prompt=self._system_prompt(evidence),
                input_text=str(query),
                context_length=profile.context_length,
                reasoning=profile.reasoning,
                max_output_tokens=profile.max_output_tokens,
                temperature=profile.temperature,
            )
            if result.model_instance_id != resident_id:
                raise LocalModelEndpointError(
                    "R21H warm FAST chat instance mismatch after exact "
                    "post-evidence residency proof: "
                    f"expected={resident_id} actual={result.model_instance_id}"
                )
            return TwinAnswer(
                text=result.text,
                model=profile.model,
                mode="fast",
                evidence=tuple(evidence),
                stats=result.stats,
                reasoning_present=result.reasoning is not None,
            )
