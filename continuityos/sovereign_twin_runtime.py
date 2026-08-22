"""R21F Sovereign Twin runtime overlay: FAST load-ACK timeout residency reconciliation.

R21E is retained byte-exact in sovereign_twin_runtime_r21e.py. Native DEEP remains
R21E behavior. R21F changes only the cold FAST acquisition path: one explicit
/models/load request uses a bounded ACK window; a transport timeout never causes a
second load request and may be reconciled by exact read-only FAST residency proof
within the original load_timeout budget.
"""
from __future__ import annotations

from time import perf_counter as _system_perf_counter, sleep as _system_sleep
from typing import Any, Mapping
from urllib.error import HTTPError
from urllib.request import urlopen

from . import sovereign_twin_runtime_r21e as _r21e
from .sovereign_twin_runtime_r21e import *  # noqa: F401,F403

# Preserve complete R21E import surface, including underscore-prefixed helpers.
for _legacy_name, _legacy_value in vars(_r21e).items():
    if not _legacy_name.startswith("__"):
        globals().setdefault(_legacy_name, _legacy_value)
del _legacy_name, _legacy_value

# Preserve timing / transport monkeypatch semantics across retained overlays.
perf_counter = _system_perf_counter
sleep = _system_sleep
_r21e.perf_counter = lambda: perf_counter()
_r21e.sleep = lambda seconds: sleep(seconds)
_r21e.urlopen = lambda *args, **kwargs: urlopen(*args, **kwargs)

FAST_LOAD_ACK_TIMEOUT_SECONDS = 20.0
FAST_ACQUISITION_POLL_SECONDS = 0.5


def _looks_like_fast_load_ack_timeout(exc: BaseException) -> bool:
    """Accept only transport-level timeout evidence, never HTTP/capacity failures."""
    capacity_check = getattr(_r21e, "_looks_like_capacity_error", None)
    if callable(capacity_check) and capacity_check(str(exc)):
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
    return "timeouterror: timed out" in value or value.endswith(": timed out")


class _FastResidencyUnsafeError(LocalModelEndpointError):
    """Observed FAST residency exists but cannot satisfy the exact profile contract."""


class LmStudioClient(_r21e.LmStudioClient):
    """R21E client unchanged; R21F FAST reconciliation is runtime-owned."""


class SovereignTwinRuntime(_r21e.SovereignTwinRuntime):
    """R21E runtime plus fail-closed FAST load-ACK timeout reconciliation."""

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

    def _probe_exact_fast_residency(
        self,
        profile: LocalModelProfile,
        *,
        expected_id: str | None = None,
    ) -> str | None:
        """Return exact FAST id, None if cold, or fail if observed residency is unsafe."""
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
            raise _FastResidencyUnsafeError(
                "FAST loaded_instances is invalid during acquisition proof"
            )
        if len(raw_instances) != 1:
            raise _FastResidencyUnsafeError(
                "FAST acquisition did not produce exactly one resident instance"
            )

        instance = raw_instances[0]
        if not isinstance(instance, Mapping):
            raise _FastResidencyUnsafeError(
                "FAST loaded instance is invalid during acquisition proof"
            )
        instance_id = instance.get("id")
        if not isinstance(instance_id, str) or not instance_id:
            raise _FastResidencyUnsafeError(
                "FAST loaded instance is missing id during acquisition proof"
            )
        if expected_id is not None and instance_id != expected_id:
            raise _FastResidencyUnsafeError(
                "FAST explicit acquisition instance id mismatch: "
                f"expected={expected_id} actual={instance_id}"
            )
        try:
            loaded_context = self._instance_context(instance, label="FAST")
        except LocalModelEndpointError as exc:
            raise _FastResidencyUnsafeError(str(exc)) from exc
        if loaded_context != profile.context_length:
            raise _FastResidencyUnsafeError(
                "FAST explicit acquisition context_length mismatch: "
                f"expected={profile.context_length} actual={loaded_context}"
            )
        return instance_id

    def _wait_for_fast_residency(
        self,
        profile: LocalModelProfile,
        *,
        deadline: float,
    ) -> str:
        """Poll read-only residency until exact FAST appears or original load budget expires."""
        last_endpoint_error: LocalModelEndpointError | None = None
        while True:
            try:
                instance_id = self._probe_exact_fast_residency(profile)
            except _FastResidencyUnsafeError:
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
                    "FAST did not become exactly resident before original load_timeout budget expired"
                    + detail
                )
            sleep(min(FAST_ACQUISITION_POLL_SECONDS, remaining))

    def _ensure_fast_loaded(self, profile: LocalModelProfile) -> str:
        """Warm exact FAST or issue one cold load and reconcile an ACK timeout by residency."""
        existing_id = self._probe_exact_fast_residency(profile)
        if existing_id is not None:
            return existing_id

        load_for_acquisition = getattr(self.client, "load_for_acquisition", None)
        if not callable(load_for_acquisition):
            # Preserve compatibility for custom clients that implement only legacy load().
            return super()._ensure_fast_loaded(profile)

        acquisition_started = perf_counter()
        load_timeout = max(
            0.001,
            float(getattr(self.client, "load_timeout", 600.0)),
        )
        acquired_id: str | None = None
        load_ack_timed_out = False
        try:
            acquired_id = str(
                load_for_acquisition(
                    model=profile.model,
                    context_length=profile.context_length,
                    ack_timeout=min(FAST_LOAD_ACK_TIMEOUT_SECONDS, load_timeout),
                )
            )
        except LocalModelEndpointError as exc:
            if not _looks_like_fast_load_ack_timeout(exc):
                raise LocalModelEndpointError(
                    f"FAST explicit load failed before chat: {exc}"
                ) from exc
            load_ack_timed_out = True

        if load_ack_timed_out:
            return self._wait_for_fast_residency(
                profile,
                deadline=acquisition_started + load_timeout,
            )

        if not acquired_id:
            raise LocalModelEndpointError(
                "FAST explicit load returned an empty instance id"
            )
        proven_id = self._probe_exact_fast_residency(
            profile,
            expected_id=acquired_id,
        )
        if proven_id is None:
            raise LocalModelEndpointError(
                "FAST explicit acquisition did not produce a resident instance"
            )
        return proven_id
