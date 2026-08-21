"""R21C Sovereign Twin runtime overlay: residency-authoritative native DEEP acquisition.

The R21B runtime is kept byte-exact in sovereign_twin_runtime_r21b.py. This module
re-exports its public contract and changes only native DEEP acquisition semantics:
a bounded load-ACK timeout may be reconciled by exact read-only residency proof.
"""
from __future__ import annotations

from time import perf_counter as _system_perf_counter, sleep as _system_sleep
from typing import Any, Mapping
from urllib.error import HTTPError

from . import sovereign_twin_runtime_r21b as _base
from .sovereign_twin_runtime_r21b import *  # noqa: F401,F403

# R21B historically exposes several underscore-prefixed helpers that are imported
# directly by tests and local callers. Python star-import intentionally omits them,
# so mirror every non-dunder base attribute before applying the R21C overrides.
for _legacy_name, _legacy_value in vars(_base).items():
    if not _legacy_name.startswith("__"):
        globals().setdefault(_legacy_name, _legacy_value)
del _legacy_name, _legacy_value

# Keep R21B timing monkeypatch semantics for existing tests/callers importing this module.
perf_counter = _system_perf_counter
sleep = _system_sleep
_base.perf_counter = lambda: perf_counter()

DEEP_LOAD_ACK_TIMEOUT_SECONDS = 20.0
DEEP_ACQUISITION_POLL_SECONDS = 0.5


def _looks_like_load_ack_timeout(exc: BaseException) -> bool:
    """Accept only transport-level timeout evidence, never HTTP/capacity failures."""
    if _base._looks_like_capacity_error(str(exc)):
        return False

    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, HTTPError):
            return False
        if isinstance(current, TimeoutError):
            return True
        next_exc = current.__cause__ if current.__cause__ is not None else current.__context__
        current = next_exc if isinstance(next_exc, BaseException) else None

    value = str(exc).lower()
    if "httperror:" in value or "http error " in value:
        return False
    return "timeouterror: timed out" in value


class _DeepResidencyUnsafeError(LocalModelEndpointError):
    """Observed DEEP residency exists but cannot satisfy the exact acquisition contract."""


class LmStudioClient(_base.LmStudioClient):
    """R21B client plus a bounded ACK-only loader for native DEEP acquisition."""

    @staticmethod
    def _validate_load_response(data: Any, *, context_length: int) -> str:
        if not isinstance(data, Mapping) or data.get("status") != "loaded":
            raise LocalModelEndpointError("LM Studio model load did not report status=loaded")
        instance_id_raw = data.get("instance_id")
        if not isinstance(instance_id_raw, str) or not instance_id_raw:
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

    def load_for_acquisition(
        self,
        *,
        model: str,
        context_length: int,
        ack_timeout: float,
    ) -> str:
        """Issue exactly one explicit load with bounded ACK wait; residency is proven separately."""
        request_timeout = min(
            self.load_timeout,
            max(0.001, float(ack_timeout)),
        )
        try:
            data = self._request(
                "POST",
                "/api/v1/models/load",
                {
                    "model": str(model),
                    "context_length": int(context_length),
                    "echo_load_config": True,
                },
                timeout=request_timeout,
            )
        except LocalModelEndpointError as exc:
            raise LocalModelEndpointError(
                "LM Studio model load failed with "
                f"load_ack_timeout={request_timeout:g}s: {exc}"
            ) from exc
        return self._validate_load_response(data, context_length=context_length)


class SovereignTwinRuntime(_base.SovereignTwinRuntime):
    """R21B runtime with residency-authoritative native DEEP acquisition."""

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

    def _probe_exact_deep_residency(
        self,
        profile: LocalModelProfile,
        *,
        expected_id: str | None = None,
    ) -> str | None:
        """Return exact DEEP id, None if cold, or fail if observed residency is unsafe."""
        rows = self.client.models()
        row = next(
            (item for item in rows if str(item.get("key")) == str(profile.model)),
            None,
        )
        if row is None:
            return None

        raw_instances = row.get("loaded_instances")
        if raw_instances in (None, []):
            return None
        if not isinstance(raw_instances, list):
            raise _DeepResidencyUnsafeError(
                "DEEP loaded_instances is invalid during acquisition proof"
            )
        if len(raw_instances) != 1:
            raise _DeepResidencyUnsafeError(
                "DEEP acquisition did not produce exactly one resident instance"
            )

        instance = raw_instances[0]
        if not isinstance(instance, Mapping):
            raise _DeepResidencyUnsafeError(
                "DEEP loaded instance is invalid during acquisition proof"
            )
        instance_id = instance.get("id")
        if not isinstance(instance_id, str) or not instance_id:
            raise _DeepResidencyUnsafeError(
                "DEEP loaded instance is missing id during acquisition proof"
            )
        if expected_id is not None and instance_id != expected_id:
            raise _DeepResidencyUnsafeError(
                "DEEP explicit acquisition instance id mismatch: "
                f"expected={expected_id} actual={instance_id}"
            )
        try:
            loaded_context = self._instance_context(instance, label="DEEP")
        except LocalModelEndpointError as exc:
            raise _DeepResidencyUnsafeError(str(exc)) from exc
        if loaded_context != profile.context_length:
            raise _DeepResidencyUnsafeError(
                "DEEP explicit acquisition context_length mismatch: "
                f"expected={profile.context_length} actual={loaded_context}"
            )
        return instance_id

    def _wait_for_deep_residency(
        self,
        profile: LocalModelProfile,
        *,
        deadline: float,
    ) -> str:
        """Poll read-only residency until exact DEEP appears or acquisition budget expires."""
        last_endpoint_error: LocalModelEndpointError | None = None
        while True:
            try:
                instance_id = self._probe_exact_deep_residency(profile)
            except _DeepResidencyUnsafeError:
                raise
            except LocalModelEndpointError as exc:
                last_endpoint_error = exc
            else:
                if instance_id is not None:
                    return instance_id

            remaining = deadline - perf_counter()
            if remaining <= 0:
                detail = (
                    f"; last residency read error={last_endpoint_error}"
                    if last_endpoint_error is not None
                    else ""
                )
                raise LocalModelEndpointError(
                    "DEEP did not become exactly resident before acquisition deadline"
                    + detail
                )
            sleep(min(DEEP_ACQUISITION_POLL_SECONDS, remaining))

    def _cleanup_failed_deep_acquisition(
        self,
        profile: LocalModelProfile,
        *,
        acquired_id: str | None = None,
    ) -> None:
        cleanup_ids: list[str] = []
        if acquired_id:
            cleanup_ids.append(acquired_id)
        try:
            for value in self._strict_loaded_instance_ids(profile.model, label="DEEP"):
                if value not in cleanup_ids:
                    cleanup_ids.append(value)
        except LocalModelEndpointError:
            pass
        self._cleanup_deep_ids_best_effort(cleanup_ids)

    def _acquire_deep(
        self,
        profile: LocalModelProfile,
    ) -> tuple[str, dict[str, float]]:
        """Issue one load; after ACK timeout, exact residency becomes authoritative."""
        phase_timings_ms: dict[str, float] = {}

        phase_started = perf_counter()
        existing = self._strict_loaded_instance_ids(profile.model, label="DEEP")
        phase_timings_ms["deep_pre_acquire_proof"] = self._elapsed_ms(phase_started)
        if existing:
            raise LocalModelEndpointError(
                "DEEP already resident before explicit acquisition; refusing native DEEP"
            )

        load = getattr(self.client, "load", None)
        load_for_acquisition = getattr(self.client, "load_for_acquisition", None)
        if not callable(load) and not callable(load_for_acquisition):
            raise LocalModelEndpointError(
                "DEEP is cold and client cannot explicitly load it"
            )

        acquisition_started = perf_counter()
        load_timeout = max(
            0.001,
            float(getattr(self.client, "load_timeout", 600.0)),
        )
        acquired_id: str | None = None
        load_ack_timed_out = False
        try:
            if callable(load_for_acquisition):
                acquired_id = str(
                    load_for_acquisition(
                        model=profile.model,
                        context_length=profile.context_length,
                        ack_timeout=min(DEEP_LOAD_ACK_TIMEOUT_SECONDS, load_timeout),
                    )
                )
            else:
                assert callable(load)
                acquired_id = str(
                    load(model=profile.model, context_length=profile.context_length)
                )
        except LocalModelEndpointError as exc:
            phase_timings_ms["deep_load"] = self._elapsed_ms(acquisition_started)
            if _base._looks_like_capacity_error(str(exc)):
                self._cleanup_failed_deep_acquisition(profile)
                raise DeepCapacityBlockedError(DEEP_CAPACITY_BLOCKED_MESSAGE) from exc
            if not callable(load_for_acquisition) or not _looks_like_load_ack_timeout(exc):
                self._cleanup_failed_deep_acquisition(profile)
                raise LocalModelEndpointError(
                    f"DEEP explicit load failed before chat: {exc}"
                ) from exc
            load_ack_timed_out = True
        else:
            phase_timings_ms["deep_load"] = self._elapsed_ms(acquisition_started)

        phase_started = perf_counter()
        try:
            if load_ack_timed_out:
                acquired_id = self._wait_for_deep_residency(
                    profile,
                    deadline=acquisition_started + load_timeout,
                )
            else:
                if not acquired_id:
                    raise LocalModelEndpointError(
                        "DEEP explicit load returned an empty instance id"
                    )
                proven_id = self._probe_exact_deep_residency(
                    profile,
                    expected_id=acquired_id,
                )
                if proven_id is None:
                    raise LocalModelEndpointError(
                        "DEEP explicit acquisition did not produce a resident instance"
                    )
                acquired_id = proven_id
        except LocalModelEndpointError:
            self._cleanup_failed_deep_acquisition(
                profile,
                acquired_id=acquired_id,
            )
            raise

        phase_timings_ms["deep_acquisition_proof"] = self._elapsed_ms(phase_started)
        assert acquired_id is not None
        return acquired_id, phase_timings_ms
