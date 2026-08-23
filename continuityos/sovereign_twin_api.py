"""R21H Sovereign Twin API overlay: prewarm FAST before HTTP bind.

The R21G API is retained byte-exact in sovereign_twin_api_r21g.py. Request
handlers and all existing endpoints remain inherited. R21H changes only service
startup: exact FAST is prewarmed through the R21H runtime before the listening
socket is created, so a successfully bound server is already warm for FAST.
"""
from __future__ import annotations

from threading import Lock

from . import sovereign_twin_api_r21g as _r21g_api
from .sovereign_twin_api_r21g import *  # noqa: F401,F403
from .sovereign_twin_runtime import (
    DEFAULT_EMBEDDING_MODEL,
    LmStudioClient,
    LocalModelEndpointError,
    SovereignTwinRuntime,
)

# Preserve the complete R21G API import surface, including underscore-prefixed helpers.
for _legacy_name, _legacy_value in vars(_r21g_api).items():
    if not _legacy_name.startswith("__"):
        globals().setdefault(_legacy_name, _legacy_value)
del _legacy_name, _legacy_value

# Preserve monkeypatch semantics for inherited R21G request dispatch.
_r21g_api.run_deep_lite = lambda *args, **kwargs: run_deep_lite(*args, **kwargs)


_R21H_STARTUP_PREWARM_LOCK = Lock()
_R21H_STARTUP_PREWARM_STATE = "NOT_STARTED"
_R21H_STARTUP_PREWARM_RESULT = None
_R21H_STARTUP_PREWARM_ERROR = None


def _prewarm_fast_startup_once(runtime: SovereignTwinRuntime) -> dict:
    """Run the R21H startup prewarm at most once for this Python process.

    A failed or interrupted attempt is sticky: later serve() calls fail closed
    instead of issuing a second startup prewarm/model effect.
    """
    global _R21H_STARTUP_PREWARM_STATE
    global _R21H_STARTUP_PREWARM_RESULT
    global _R21H_STARTUP_PREWARM_ERROR

    with _R21H_STARTUP_PREWARM_LOCK:
        if _R21H_STARTUP_PREWARM_STATE == "SUCCEEDED":
            return dict(_R21H_STARTUP_PREWARM_RESULT or {})
        if _R21H_STARTUP_PREWARM_STATE == "FAILED":
            detail = (
                f": {_R21H_STARTUP_PREWARM_ERROR}"
                if _R21H_STARTUP_PREWARM_ERROR
                else ""
            )
            raise LocalModelEndpointError(
                "R21H FAST startup prewarm already failed in this process; "
                f"retry refused{detail}"
            )
        if _R21H_STARTUP_PREWARM_STATE != "NOT_STARTED":
            raise LocalModelEndpointError(
                "R21H FAST startup prewarm process state is invalid; retry refused"
            )

        # Consume the one process-wide startup attempt before any model effect.
        _R21H_STARTUP_PREWARM_STATE = "RUNNING"
        try:
            result = dict(runtime.prewarm_fast_startup())
        except BaseException as exc:
            _R21H_STARTUP_PREWARM_ERROR = f"{type(exc).__name__}: {exc}"
            _R21H_STARTUP_PREWARM_STATE = "FAILED"
            raise

        _R21H_STARTUP_PREWARM_RESULT = result
        _R21H_STARTUP_PREWARM_STATE = "SUCCEEDED"
        return dict(_R21H_STARTUP_PREWARM_RESULT)


def serve(
    *,
    memory_db: str,
    base_url: str = "http://127.0.0.1:1234",
    host: str = "127.0.0.1",
    port: int = 8765,
    admission_path: str | None = None,
    embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    fast_startup_prewarm: bool = True,
) -> None:
    """Serve only after R21H FAST startup prewarm succeeds.

    Setting ``fast_startup_prewarm=False`` preserves the historical R21G startup
    behavior for explicit library callers. The existing CLI omits this argument,
    so R21H service startup is prewarm-on by default.
    """
    host = _r21g_api._validate_bind(host)
    runtime = SovereignTwinRuntime(
        memory_db,
        client=LmStudioClient(base_url),
        embedding_model=embedding_model,
    )
    server = None
    try:
        if fast_startup_prewarm:
            startup_prewarm = _prewarm_fast_startup_once(runtime)
        else:
            startup_prewarm = {
                "ok": True,
                "skipped": True,
                "execution_authority": "NONE",
                "can_execute": False,
            }

        queue_path = admission_path or str(
            _r21g_api.Path(memory_db).with_suffix(".twin-admissions.jsonl")
        )
        admissions = _r21g_api.ShadowMemoryAdmissionQueue(queue_path)

        # Construction binds the socket. Keep it strictly after successful
        # prewarm so a bound R21H server never advertises a cold FAST startup.
        server = _r21g_api._TwinServer((host, int(port)), _r21g_api._Handler)
        server.runtime = runtime
        server.admissions = admissions
        server.startup_prewarm = startup_prewarm
        server.serve_forever()
    finally:
        if server is not None:
            server.server_close()
        runtime.close()
