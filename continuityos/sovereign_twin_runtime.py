"""R21H Sovereign Twin runtime overlay: startup FAST streaming-JIT prewarm.

R21G is retained byte-exact in sovereign_twin_runtime_r21g.py. R21H does not
change ordinary FAST or DEEP request behavior. It adds one explicit startup
prewarm hook that reuses the exact R21G cold FAST chat-coupled streaming-JIT
path with empty evidence, so startup acquisition never calls the historical
explicit FAST loader and never reads or writes Sovereign Twin memory.
"""
from __future__ import annotations

from typing import Any

from . import sovereign_twin_runtime_r21g as _r21g
from .sovereign_twin_runtime_r21g import *  # noqa: F401,F403

# Preserve the complete R21G import surface, including underscore-prefixed helpers.
for _legacy_name, _legacy_value in vars(_r21g).items():
    if not _legacy_name.startswith("__"):
        globals().setdefault(_legacy_name, _legacy_value)
del _legacy_name, _legacy_value

# Preserve timing / transport monkeypatch semantics across the R21H facade.
_r21g.perf_counter = lambda: perf_counter()
_r21g.sleep = lambda seconds: sleep(seconds)
_r21g.urlopen = lambda *args, **kwargs: urlopen(*args, **kwargs)

FAST_STARTUP_PREWARM_QUERY = (
    "Sovereign Twin startup prewarm only. Reply exactly FAST_PREWARM_OK."
)


class SovereignTwinRuntime(_r21g.SovereignTwinRuntime):
    """R21G runtime plus fail-closed startup FAST prewarm."""

    def prewarm_fast_startup(self) -> dict[str, Any]:
        """Make exact FAST chat-ready before API bind without touching memory.

        Already-resident exact FAST is a no-op. Cold FAST must use the dedicated
        R21G streaming-JIT transport; compatibility fallback to explicit loading
        is intentionally forbidden for startup prewarm.
        """
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
                    "acquisition_signal": "already_resident",
                    "acquisition_event_type": "already_resident",
                    "model_load_end_seen": False,
                    "jit_load_time_seconds": None,
                    "stream_event_types": [],
                    "execution_authority": "NONE",
                    "can_execute": False,
                }

            stream_chat = getattr(
                self.client,
                "chat_fast_streaming_jit_reconciled",
                None,
            )
            if not callable(stream_chat):
                raise LocalModelEndpointError(
                    "R21H FAST startup prewarm requires the R21G streaming-JIT "
                    "transport; explicit-load compatibility fallback is forbidden"
                )

            # Deliberately bypass evidence(query): startup prewarm is acquisition
            # only and must not read or mutate Sovereign Twin memory.
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
