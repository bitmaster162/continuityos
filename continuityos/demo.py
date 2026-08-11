"""Self-contained proof of ContinuityOS continuity across a fresh process.

The public ``cos demo continuity`` flow never resolves or opens the user's normal
ContinuityOS database.  It creates an ephemeral database, writes a known state,
closes the writer, and asks a separate Python process to recover that state using
only the persisted database.  The temporary directory is removed before return.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence

from .continuity import Continuity
from .db import context_identity
from .embed import HashingEmbedder
from .memory import Memory

SCHEMA = "continuityos.product_demo_continuity/v1"
PROBE_SCHEMA = "continuityos.product_demo_continuity_probe/v1"

CANON_TEXT = "Continuity survives model and session boundaries through durable state."
TRUNK_TEXT = "Prove durable continuity across a fresh process"
CASH_TEXT = "Keep the proof local, deterministic, and inspectable"
LOOP_TEXT = "Complete the isolated continuity proof"
NEXT_ACTION = "Continue from the recovered checkpoint"
SUMMARY_TEXT = "Ephemeral state persisted before the session boundary"
PROOF_TEXT = "fresh-process continuity demo"
FACT_KEY = "continuity-demo-marker"


def _effects(
    *,
    ephemeral_filesystem_write: bool = False,
    ephemeral_memory_write: bool = False,
    subprocess_execution: bool = False,
    cleanup_pass: bool | None = None,
) -> dict[str, object]:
    return {
        "ephemeral_filesystem_write": bool(ephemeral_filesystem_write),
        "ephemeral_memory_write": bool(ephemeral_memory_write),
        "user_memory_read": False,
        "user_memory_write": False,
        "client_config_write": False,
        "network_effect": False,
        "external_model_call": False,
        "subprocess_execution": bool(subprocess_execution),
        "server_started": False,
        "deployment": False,
        "agent_dispatch": False,
        "trading": False,
        "wallet_access": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "temporary_cleanup_pass": cleanup_pass,
    }


def _hold(
    reason: str,
    *,
    error: str | None = None,
    effects: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": SCHEMA,
        "terminal": "COS_DEMO_CONTINUITY_HOLD",
        "reason": reason,
        "effects": dict(effects or _effects()),
    }
    if error:
        value["error"] = error
    return value


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _fact_text(marker: str) -> str:
    return f"Continuity demo marker: {marker}"


def _memory(path: str | Path, *, read_only: bool = False) -> Memory:
    # Pass the zero-dependency embedder explicitly so the proof emits no optional
    # dependency warning to stderr.  The demo is about persistence, not embedding quality.
    return Memory(str(path), embedder=HashingEmbedder(), read_only=read_only)


def _write_demo_state(db_path: Path, marker: str) -> dict[str, Any]:
    m = _memory(db_path)
    c = Continuity(memory=m)
    try:
        canon_id = c.add_canon(CANON_TEXT)
        fact_id = m.upsert(_fact_text(marker), namespace="facts", key=FACT_KEY, mtype="fact")
        trunk_id = c.set_frontier("trunk", TRUNK_TEXT)
        cash_id = c.set_frontier("cash", CASH_TEXT)
        loop_id = c.add_loop(LOOP_TEXT)
        checkpoint_id = c.checkpoint(summary=SUMMARY_TEXT, next_action=NEXT_ACTION, proof=PROOF_TEXT)
        memory_count = m.count()
        # The demo owns this temporary DB, so explicitly checkpoint its WAL before
        # closing the writer.  A non-zero first field means SQLite could not fully
        # checkpoint; that is a failed durability proof, not something to hide.
        wal = m.store.con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        wal_values = list(wal) if wal is not None else None
        if not wal_values or int(wal_values[0]) != 0:
            raise RuntimeError(f"temporary WAL checkpoint did not quiesce: {wal_values!r}")
        return {
            "canon_id": canon_id,
            "fact_id": fact_id,
            "trunk_id": trunk_id,
            "cash_id": cash_id,
            "loop_id": loop_id,
            "checkpoint_id": checkpoint_id,
            "memory_count": memory_count,
            "wal_checkpoint": wal_values,
        }
    finally:
        m.store.con.close()


def _probe(db_path: str, marker: str) -> tuple[dict[str, Any], int]:
    path = Path(db_path)
    if not path.is_file():
        return ({
            "schema": PROBE_SCHEMA,
            "terminal": "COS_DEMO_CONTINUITY_PROBE_FAIL",
            "reason": "DEMO_DB_NOT_FOUND",
        }, 2)

    try:
        m = _memory(path, read_only=True)
        c = Continuity(memory=m)
    except Exception as exc:
        return ({
            "schema": PROBE_SCHEMA,
            "terminal": "COS_DEMO_CONTINUITY_PROBE_FAIL",
            "reason": "FRESH_OPEN_FAILED",
            "error": f"{type(exc).__name__}: {exc}",
        }, 2)

    try:
        fact = m.find("facts", FACT_KEY)
        canon_rows = c._dump("canon")
        frontiers = c.frontiers()
        loops = c.open_loops()
        checkpoint = c.last_checkpoint()
        doctor = c.doctor()
        handoff = c.handoff()
        identity = context_identity(c)

        checks = {
            "fact_recovered": bool(fact and fact.text == _fact_text(marker)),
            "canon_recovered": any(row.get("text") == CANON_TEXT for row in canon_rows),
            "trunk_recovered": frontiers.get("trunk") == TRUNK_TEXT,
            "cash_recovered": frontiers.get("cash") == CASH_TEXT,
            "open_loop_recovered": any(loop.get("text") == LOOP_TEXT for loop in loops),
            "checkpoint_recovered": bool(
                checkpoint
                and (checkpoint.get("meta") or {}).get("summary") == SUMMARY_TEXT
                and (checkpoint.get("meta") or {}).get("proof") == PROOF_TEXT
            ),
            "next_action_recovered": bool(
                checkpoint and (checkpoint.get("meta") or {}).get("next") == NEXT_ACTION
            ),
            "doctor_healthy": doctor.get("healthy") is True,
            "handoff_reconstructed": all(
                token in handoff
                for token in (CANON_TEXT, TRUNK_TEXT, CASH_TEXT, LOOP_TEXT, NEXT_ACTION)
            ),
        }
        passed = sum(1 for ok in checks.values() if ok)
        total = len(checks)
        terminal = "COS_DEMO_CONTINUITY_PROBE_PASS" if passed == total else "COS_DEMO_CONTINUITY_PROBE_FAIL"
        return ({
            "schema": PROBE_SCHEMA,
            "terminal": terminal,
            "reason": "FRESH_PROCESS_RECOVERY_VERIFIED" if passed == total else "RECOVERY_MISMATCH",
            "process_id": os.getpid(),
            "memory_count": m.count(),
            "context_sha256": identity.get("context_sha256"),
            "doctor": {
                "healthy": doctor.get("healthy"),
                "passed": doctor.get("passed"),
                "total": doctor.get("total"),
            },
            "checks": checks,
            "passed": passed,
            "total": total,
        }, 0 if passed == total else 2)
    except Exception as exc:
        return ({
            "schema": PROBE_SCHEMA,
            "terminal": "COS_DEMO_CONTINUITY_PROBE_FAIL",
            "reason": "RECOVERY_READ_FAILED",
            "error": f"{type(exc).__name__}: {exc}",
        }, 2)
    finally:
        m.store.con.close()


def _probe_process(db_path: Path, marker: str, *, timeout: float = 20.0) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "continuityos.demo",
        "_probe-continuity",
        "--db",
        str(db_path),
        "--marker",
        marker,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return {
            "ok": False,
            "started": isinstance(exc, subprocess.TimeoutExpired),
            "reason": "FRESH_PROCESS_START_FAILED",
            "error": f"{type(exc).__name__}: {exc}",
            "command": command,
        }

    try:
        value = json.loads(completed.stdout)
    except Exception as exc:
        return {
            "ok": False,
            "started": True,
            "reason": "FRESH_PROCESS_OUTPUT_INVALID",
            "returncode": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
            "error": f"{type(exc).__name__}: {exc}",
            "command": command,
        }

    ok = (
        completed.returncode == 0
        and isinstance(value, dict)
        and value.get("terminal") == "COS_DEMO_CONTINUITY_PROBE_PASS"
    )
    return {
        "ok": ok,
        "started": True,
        "reason": "FRESH_PROCESS_PASS" if ok else "FRESH_PROCESS_FAIL",
        "returncode": completed.returncode,
        "probe": value,
        "stderr": completed.stderr[-4000:],
        "command": command,
    }


def run_continuity(*, timeout: float = 20.0) -> tuple[dict[str, Any], int]:
    marker = secrets.token_hex(16)
    filesystem_write = False
    memory_write = False
    subprocess_execution = False

    try:
        root = Path(tempfile.mkdtemp(prefix="continuityos-demo-"))
    except Exception as exc:
        return (_hold(
            "TEMPORARY_DIRECTORY_CREATE_FAILED",
            error=f"{type(exc).__name__}: {exc}",
            effects=_effects(),
        ), 2)

    filesystem_write = True
    db_path = root / "demo_memory.db"
    value: dict[str, Any] | None = None
    code = 2
    cleanup_error: str | None = None

    try:
        try:
            memory_write = True
            written = _write_demo_state(db_path, marker)
            db_sha256 = _sha256_file(db_path)
        except Exception as exc:
            value = _hold("DEMO_STATE_WRITE_FAILED", error=f"{type(exc).__name__}: {exc}")
        else:
            fresh = _probe_process(db_path, marker, timeout=timeout)
            subprocess_execution = bool(fresh.get("started"))
            if not fresh.get("ok"):
                value = _hold(
                    "FRESH_PROCESS_RECOVERY_FAILED",
                    error=json.dumps(fresh, ensure_ascii=False, sort_keys=True),
                )
            else:
                probe = fresh["probe"]
                value = {
                    "schema": SCHEMA,
                    "terminal": "COS_DEMO_CONTINUITY_PASS",
                    "reason": "DURABLE_STATE_RECOVERED_ACROSS_FRESH_PROCESS",
                    "demo": "continuity",
                    "session_boundary": "separate_python_process",
                    "demo_db_sha256": db_sha256,
                    "written": written,
                    "recovered": {
                        "process_id": probe.get("process_id"),
                        "memory_count": probe.get("memory_count"),
                        "context_sha256": probe.get("context_sha256"),
                        "doctor": probe.get("doctor"),
                        "checks": probe.get("checks"),
                        "passed": probe.get("passed"),
                        "total": probe.get("total"),
                    },
                }
                code = 0
    finally:
        try:
            shutil.rmtree(root)
        except Exception as exc:
            cleanup_error = f"{type(exc).__name__}: {exc}"

    cleanup_pass = not root.exists()
    effects = _effects(
        ephemeral_filesystem_write=filesystem_write,
        ephemeral_memory_write=memory_write,
        subprocess_execution=subprocess_execution,
        cleanup_pass=cleanup_pass,
    )
    if value is None:
        value = _hold("DEMO_INTERNAL_ERROR", effects=effects)
    value["effects"] = effects
    value["temporary_path_removed"] = cleanup_pass
    if cleanup_error:
        value["cleanup_error"] = cleanup_error
    if not cleanup_pass:
        value["terminal"] = "COS_DEMO_CONTINUITY_HOLD"
        value["reason"] = "TEMPORARY_CLEANUP_FAILED"
        code = 2
    return value, code


def _render(value: Mapping[str, Any]) -> str:
    if value.get("terminal") != "COS_DEMO_CONTINUITY_PASS":
        lines = ["ContinuityOS continuity demo  HOLD"]
        lines.append(f"Reason        {value.get('reason', 'UNKNOWN')}")
        if value.get("error"):
            lines.append(f"Error         {value['error']}")
        lines.append(
            "User memory   UNTOUCHED"
            if not (value.get("effects") or {}).get("user_memory_write")
            else "User memory   UNKNOWN"
        )
        return "\n".join(lines)

    recovered = value.get("recovered") or {}
    checks = recovered.get("checks") or {}
    lines = ["ContinuityOS continuity demo  PASS"]
    lines.append("Boundary      separate Python process")
    for name, ok in checks.items():
        lines.append(f"  {'PASS' if ok else 'FAIL':<4}  {name}")
    doctor = recovered.get("doctor") or {}
    lines.append(f"Doctor        {'HEALTHY' if doctor.get('healthy') else 'ATTENTION'}  {doctor.get('passed')}/{doctor.get('total')}")
    lines.append("User memory   UNTOUCHED")
    lines.append("External AI   NOT USED")
    lines.append(f"Cleanup       {'PASS' if value.get('temporary_path_removed') else 'FAIL'}")
    lines.append("Result        durable state survived a fresh process and reconstructed the next work context")
    return "\n".join(lines)


def _probe_cli(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--db", required=True)
    parser.add_argument("--marker", required=True)
    args = parser.parse_args(list(argv))
    value, code = _probe(args.db, args.marker)
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return code


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if values[:1] == ["_probe-continuity"]:
        return _probe_cli(values[1:])

    parser = argparse.ArgumentParser(
        prog="cos demo",
        description="Run self-contained product proofs without touching your normal memory DB",
    )
    parser.add_argument("demo", choices=["continuity"])
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--timeout", type=float, default=20.0, help="fresh-process probe timeout in seconds")
    parser.add_argument("--db", dest="forbidden_db", default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(values)

    if args.forbidden_db is not None:
        value = _hold("USER_DB_ARGUMENT_NOT_ALLOWED", effects=_effects(cleanup_pass=True))
        code = 2
    else:
        value, code = run_continuity(timeout=max(1.0, args.timeout))

    if args.as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render(value))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
