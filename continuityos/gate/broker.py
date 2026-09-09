"""GateBroker A1 — fail-closed, no invented APIs."""
import contextlib
import hashlib
import io
import json
import os
import shlex
import sqlite3
import subprocess
import tempfile
import threading
import time

from continuityos.gate import cli
from continuityos.gate.ledger import Ledger
from continuityos.gate.spec import ActionSpec


_ACTION_FIELDS = ("tool", "command", "args", "paths", "cwd", "agent")
_HASH_RE = "0123456789abcdef"
_OUTPUT_LIMIT = 64 * 1024
_ENV_ALLOWLIST = (
    "COMSPEC", "HOME", "LANG", "LC_ALL", "PATH", "PATHEXT", "SystemRoot",
    "TEMP", "TMP", "USERPROFILE", "WINDIR",
)

# contextlib redirects process-global sys.stdout/sys.stderr. Broker instances
# therefore share this lock even though their request/registry locks are local.
_STDIO_REDIRECT_LOCK = threading.RLock()


class GateBroker:
    def __init__(self, registry_path=None, ledger_path=None, db=None):
        self.registry_path = registry_path or os.path.expanduser(
            "~/.continuityos/gate_broker.db"
        )
        self.ledger_path = ledger_path or cli.LEDGER
        self.db = db
        os.makedirs(
            os.path.dirname(os.path.abspath(self.registry_path)) or ".",
            exist_ok=True,
        )
        with sqlite3.connect(self.registry_path, timeout=30) as con:
            con.execute("PRAGMA busy_timeout=30000")
            con.execute("PRAGMA synchronous=FULL")
            con.execute(
                "CREATE TABLE IF NOT EXISTS broker_requests("
                "request_key TEXT PRIMARY KEY, "
                "action_sha256 TEXT NOT NULL, "
                "preflight_hash TEXT NOT NULL UNIQUE, "
                "created_ts REAL NOT NULL)"
            )
            con.commit()
        self._lock = threading.RLock()

    @staticmethod
    def _key(request_id):
        return hashlib.sha256(request_id.encode("utf-8")).hexdigest()

    @staticmethod
    def _canonical(argv):
        if os.name == "nt":
            return subprocess.list2cmdline(argv)
        return shlex.join(argv)

    @staticmethod
    def _base_digest(action):
        if isinstance(action, dict):
            body = {
                "tool": action.get("tool"),
                "command": action.get("command"),
                "args": action.get("args"),
                "paths": action.get("paths"),
                "cwd": action.get("cwd"),
                "agent": action.get("agent"),
            }
        else:
            body = {
                "tool": action.tool,
                "command": action.command,
                "args": action.args,
                "paths": action.paths,
                "cwd": action.cwd,
                "agent": action.agent,
            }
        canonical = json.dumps(
            body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _is_hash(value):
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(char in _HASH_RE for char in value)
        )

    @staticmethod
    def _held(request_id, request_key, reasons, preflight_hash=None):
        return {
            "request_id": request_id,
            "request_key": request_key,
            "preflight_hash": preflight_hash,
            "decision": "HELD",
            "state": "HELD",
            "reused": False,
            "reasons": list(reasons),
        }

    @classmethod
    def _validated_event(cls, event, request_key, expected_digest):
        """Return (decision, error) for a durable preflight event."""
        if not isinstance(event, dict) or event.get("kind") != "preflight":
            return None, "event missing or wrong kind"
        event_hash = event.get("hash")
        if not cls._is_hash(event_hash):
            return None, "preflight_hash not lowercase 64 hex"
        payload = event.get("payload")
        if not isinstance(payload, dict):
            return None, "payload not dict"
        action = payload.get("action")
        if not isinstance(action, dict):
            return None, "action not dict"
        meta = action.get("meta")
        if not isinstance(meta, dict):
            return None, "meta not dict"
        if meta.get("broker_request_key") != request_key:
            return None, "broker_request_key mismatch"
        if any(field not in action for field in _ACTION_FIELDS):
            return None, "action is incomplete"
        if (
            not isinstance(action["tool"], str)
            or not isinstance(action["command"], str)
            or not isinstance(action["cwd"], str)
            or not isinstance(action["agent"], str)
            or not isinstance(action["args"], list)
            or not isinstance(action["paths"], list)
            or not all(isinstance(value, str) for value in action["args"])
            or not all(isinstance(value, str) for value in action["paths"])
        ):
            return None, "action fields have invalid types"
        digest = cls._base_digest(action)
        if digest != expected_digest:
            return None, "broker_action_sha256 mismatch"
        if meta.get("broker_action_sha256") != digest:
            return None, "broker_action_sha256 marker mismatch"
        if not isinstance(payload.get("rollback_plan"), dict):
            return None, "rollback_plan not dict"
        decision = payload.get("decision")
        if not isinstance(decision, str):
            return None, "decision not str"
        return decision, None

    def _registry_mapping(self, reg, request_key):
        row = reg.execute(
            "SELECT action_sha256, preflight_hash FROM broker_requests "
            "WHERE request_key = ?",
            (request_key,),
        ).fetchone()
        return None if row is None else (row[0], row[1])

    def _adopt_or_hold(self, reg, request_id, request_key, action_digest,
                       preflight_hash, decision):
        """Handle an INSERT race without creating a second preflight."""
        try:
            reg.execute(
                "INSERT INTO broker_requests("
                "request_key, action_sha256, preflight_hash, created_ts"
                ") VALUES (?, ?, ?, ?)",
                (request_key, action_digest, preflight_hash, time.time()),
            )
            reg.commit()
        except sqlite3.IntegrityError:
            reg.rollback()
            reg.execute("BEGIN IMMEDIATE")
            mapping = self._registry_mapping(reg, request_key)
            reg.commit()
            if mapping is None:
                return self._held(
                    request_id, request_key,
                    ["race conflict: row disappeared after integrity error"],
                )
            existing_digest, existing_hash = mapping
            if (
                existing_digest == action_digest
                and existing_hash == preflight_hash
            ):
                return {
                    "request_id": request_id,
                    "request_key": request_key,
                    "preflight_hash": existing_hash,
                    "decision": decision,
                    "state": "REUSED",
                    "reused": True,
                    "reasons": ["race resolved; adopted exact mapping"],
                }
            return self._held(
                request_id, request_key,
                ["race conflict: existing mapping differs"],
                preflight_hash=existing_hash,
            )
        return {
            "request_id": request_id,
            "request_key": request_key,
            "preflight_hash": preflight_hash,
            "decision": decision,
            "state": "PREFLIGHTED",
            "reused": False,
            "reasons": [],
        }

    def _load_adapter(self, spec):
        """Mirror cli._decide adapter wiring without constructing another spec."""
        cli._require_legacy_gate()
        try:
            policy = cli.load_policy(cli.discover_policy(cli.HOME))
        except (cli.PolicyError, OSError) as exc:
            policy = cli.default_policy()
            spec.meta["policy_error"] = f"{type(exc).__name__}: {exc}"
        context, context_error, _context_identity = cli._context(self.db)
        if context_error:
            spec.meta["context_error"] = context_error
        return policy, context

    def preflight_exec(self, request_id, argv, cwd, paths=None):
        if not isinstance(request_id, str) or not (1 <= len(request_id) <= 256):
            return self._held(request_id, None, ["bad request_id"])
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(value, str) for value in argv)
        ):
            return self._held(request_id, None, ["bad argv"])
        if not isinstance(cwd, str) or not os.path.isabs(cwd):
            return self._held(request_id, None, ["cwd not absolute"])
        cwd = os.path.abspath(
            os.path.realpath(os.path.expandvars(os.path.expanduser(cwd)))
        )
        paths = list(paths) if paths is not None else []
        if not all(isinstance(value, str) for value in paths):
            return self._held(request_id, None, ["bad paths"])

        command = self._canonical(argv)
        spec = ActionSpec(
            tool="exec",
            command=command,
            args=list(argv),
            paths=list(paths),
            cwd=cwd,
            agent="mcp-broker",
        )
        action_digest = self._base_digest(spec)
        request_key = self._key(request_id)
        spec.meta["broker_request_key"] = request_key
        spec.meta["broker_action_sha256"] = action_digest

        try:
            policy, context = self._load_adapter(spec)
        except Exception as exc:
            return self._held(
                request_id, request_key,
                [f"adapter error: {type(exc).__name__}: {exc}"],
            )

        try:
            with self._lock:
                reg = sqlite3.connect(self.registry_path, timeout=30)
                try:
                    reg.execute("PRAGMA busy_timeout=30000")
                    reg.execute("PRAGMA synchronous=FULL")
                    reg.execute("BEGIN IMMEDIATE")

                    mapping = self._registry_mapping(reg, request_key)
                    if mapping is not None:
                        existing_digest, existing_hash = mapping
                        if existing_digest != action_digest:
                            reg.rollback()
                            return self._held(
                                request_id, request_key,
                                ["registry conflict: action_sha256 mismatch"],
                                preflight_hash=existing_hash,
                            )
                        try:
                            with Ledger(self.ledger_path) as ledger:
                                verification = ledger.verify()
                                if not verification.get("ok"):
                                    reg.rollback()
                                    return self._held(
                                        request_id, request_key,
                                        ["ledger hash chain verification failed"],
                                        preflight_hash=existing_hash,
                                    )
                                event = ledger.event(existing_hash)
                        except Exception as exc:
                            reg.rollback()
                            return self._held(
                                request_id, request_key,
                                [f"ledger event validation error: "
                                 f"{type(exc).__name__}: {exc}"],
                                preflight_hash=existing_hash,
                            )
                        decision, error = self._validated_event(
                            event, request_key, action_digest
                        )
                        if error:
                            reg.rollback()
                            return self._held(
                                request_id, request_key, [error],
                                preflight_hash=existing_hash,
                            )
                        reg.commit()
                        return {
                            "request_id": request_id,
                            "request_key": request_key,
                            "preflight_hash": existing_hash,
                            "decision": decision,
                            "state": "REUSED",
                            "reused": True,
                            "reasons": [],
                        }

                    # The registry is empty for this key. Scan the ledger while
                    # keeping the registry transaction open for orphan adoption.
                    with Ledger(self.ledger_path) as ledger:
                        verification = ledger.verify()
                        if not verification.get("ok"):
                            reg.rollback()
                            return self._held(
                                request_id, request_key,
                                ["ledger hash chain verification failed"],
                            )
                        rows = ledger.con.execute(
                            "SELECT id, hash, payload FROM events "
                            "WHERE kind = 'preflight' ORDER BY id"
                        ).fetchall()
                        matching = []
                        for _event_id, event_hash, payload_blob in rows:
                            try:
                                payload = json.loads(payload_blob)
                            except (TypeError, json.JSONDecodeError):
                                reg.rollback()
                                return self._held(
                                    request_id, request_key,
                                    ["malformed matching candidate event"],
                                )
                            if not isinstance(payload, dict):
                                reg.rollback()
                                return self._held(
                                    request_id, request_key,
                                    ["malformed matching candidate event"],
                                )
                            action = payload.get("action")
                            meta = action.get("meta") if isinstance(action, dict) else None
                            if not isinstance(meta, dict):
                                reg.rollback()
                                return self._held(
                                    request_id, request_key,
                                    ["malformed matching candidate event"],
                                )
                            if meta.get("broker_request_key") == request_key:
                                matching.append(
                                    (event_hash, payload, action, meta)
                                )

                        if len(matching) > 1:
                            reg.rollback()
                            return self._held(
                                request_id, request_key,
                                ["duplicate orphan preflight events"],
                            )
                        if len(matching) == 1:
                            event_hash, payload, action, meta = matching[0]
                            event = {
                                "kind": "preflight",
                                "hash": event_hash,
                                "payload": payload,
                            }
                            decision, error = self._validated_event(
                                event, request_key, action_digest
                            )
                            if error:
                                reg.rollback()
                                return self._held(
                                    request_id, request_key, [error],
                                    preflight_hash=event_hash,
                                )
                            return self._adopt_or_hold(
                                reg, request_id, request_key, action_digest,
                                event_hash, decision,
                            )

                        # Zero matching candidates: append exactly one preflight.
                        result = cli.preflight(
                            spec, policy=policy, ledger=ledger, context=context
                        )
                        preflight_hash = result.get("ledger_hash")
                        if not self._is_hash(preflight_hash):
                            reg.rollback()
                            return self._held(
                                request_id, request_key,
                                ["preflight result hash format invalid"],
                            )
                        verification = ledger.verify()
                        if not verification.get("ok"):
                            reg.rollback()
                            return self._held(
                                request_id, request_key,
                                ["ledger hash chain verification failed"],
                                preflight_hash=preflight_hash,
                            )
                        event = ledger.event(preflight_hash)
                        decision, error = self._validated_event(
                            event, request_key, action_digest
                        )
                        if error:
                            reg.rollback()
                            return self._held(
                                request_id, request_key, [error],
                                preflight_hash=preflight_hash,
                            )
                        return self._adopt_or_hold(
                            reg, request_id, request_key, action_digest,
                            preflight_hash, decision,
                        )
                finally:
                    try:
                        reg.close()
                    except Exception:
                        pass
        except sqlite3.Error as exc:
            return self._held(
                request_id, request_key,
                [f"registry error: {type(exc).__name__}: {exc}"],
            )
        except Exception as exc:
            return self._held(
                request_id, request_key,
                [f"state error: {type(exc).__name__}: {exc}"],
            )

    def execute_preflight(self, request_id):
        if not isinstance(request_id, str) or not (1 <= len(request_id) <= 256):
            return self._held(request_id, None, ["bad request_id"])
        request_key = self._key(request_id)
        with self._lock:
            try:
                with sqlite3.connect(self.registry_path, timeout=30) as con:
                    mapping = self._registry_mapping(con, request_key)
                if mapping is None:
                    return self._held(request_id, request_key, ["request not found in registry"])
                action_digest, preflight_hash = mapping
                if not self._is_hash(action_digest) or not self._is_hash(preflight_hash):
                    return self._held(request_id, request_key, ["registry mapping is invalid"], preflight_hash=preflight_hash)

                with Ledger(self.ledger_path) as ledger:
                    if not ledger.verify().get("ok"):
                        return self._held(request_id, request_key, ["ledger hash chain verification failed"], preflight_hash)
                    event = ledger.event(preflight_hash)
                    if event is None or event.get("hash") != preflight_hash:
                        return self._held(
                            request_id, request_key,
                            ["registry preflight_hash does not identify the exact event"],
                            preflight_hash,
                        )
                    decision, error = self._validated_event(event, request_key, action_digest)
                    if error:
                        return self._held(request_id, request_key, [error], preflight_hash)
                    payload = event["payload"]
                    action = payload["action"]
                    if action.get("tool") != "exec":
                        return self._held(request_id, request_key, ["broker permits only exec actions"], preflight_hash)
                    if decision not in ("ALLOW", "WARN", "REQUIRE_CONFIRMATION"):
                        return self._held(request_id, request_key, [f"decision not executable: {decision}"], preflight_hash)
                    expected_binding = cli._execution_binding_sha256(
                        action["command"], "exec",
                        {"action": action, "ledger_hash": preflight_hash},
                        list(action["args"]), execution_cwd=action["cwd"],
                    )
                    row = ledger._attempt_row(preflight_hash)
                    attempt = None if row is None else ledger._validate_attempt_row(row)

                if attempt is not None:
                    if attempt["binding_sha256"] != expected_binding:
                        return self._held(
                            request_id, request_key,
                            ["execution attempt binding does not match preflight"],
                            preflight_hash,
                        )
                    if attempt["phase"] == "TERMINAL":
                        return self._terminal_result(
                            request_id, request_key, preflight_hash, decision,
                            attempt, cached=True,
                        )
                    return self._held(
                        request_id, request_key,
                        [f"execution attempt is {attempt['phase']}"], preflight_hash,
                    )

                result = {
                    "decision": decision,
                    "action": action,
                    "ledger_hash": preflight_hash,
                    "rollback_plan": payload["rollback_plan"],
                }
                env = {name: os.environ[name] for name in _ENV_ALLOWLIST if name in os.environ}
                status_out, status_err = io.StringIO(), io.StringIO()
                execution_outcome = {}
                with tempfile.TemporaryFile("w+b") as child_out, tempfile.TemporaryFile("w+b") as child_err:
                    with _STDIO_REDIRECT_LOCK:
                        with contextlib.redirect_stdout(status_out), contextlib.redirect_stderr(status_err):
                            cli._execute_approved(
                                cmd=action["command"], mode="exec", result=result,
                                argv=list(action["args"]), ledger_path=self.ledger_path,
                                execution_cwd=action["cwd"], stdout=child_out,
                                stderr=child_err, env=env,
                                outcome=execution_outcome,
                            )
                    stdout_data = self._read_sink(child_out)
                    stderr_data = self._read_sink(child_err)

                with Ledger(self.ledger_path) as ledger:
                    if not ledger.verify().get("ok"):
                        return self._held(request_id, request_key, ["ledger hash chain verification failed after execution"], preflight_hash)
                    row = ledger._attempt_row(preflight_hash)
                    attempt = None if row is None else ledger._validate_attempt_row(row)
                captured = self._captured_fields(
                    stdout_data, stderr_data,
                    status_out.getvalue(), status_err.getvalue(),
                )
                claim_status = execution_outcome.get("claim_status")
                if claim_status in ("CLAIMED", "ATTEMPT_STARTED"):
                    response = self._held(
                        request_id, request_key,
                        [f"concurrent execution claim is {claim_status}; "
                         "this caller did not execute"],
                        preflight_hash,
                    )
                    response.update(captured)
                    return response
                if attempt is None or attempt["phase"] != "TERMINAL":
                    response = self._held(
                        request_id, request_key,
                        ["execution has no verified terminal state"], preflight_hash,
                    )
                    response.update(captured)
                    return response
                if attempt["binding_sha256"] != expected_binding:
                    return self._held(
                        request_id, request_key,
                        ["terminal execution binding does not match preflight"],
                        preflight_hash,
                    )
                if claim_status == "TERMINAL":
                    response = self._terminal_result(
                        request_id, request_key, preflight_hash, decision,
                        attempt, cached=True,
                    )
                elif (
                    claim_status == "CLAIMED_NEW"
                    and execution_outcome.get("claim_hash") == attempt["claim_hash"]
                ):
                    response = self._terminal_result(
                        request_id, request_key, preflight_hash, decision,
                        attempt, cached=False,
                    )
                else:
                    response = self._held(
                        request_id, request_key,
                        ["execution claim provenance is unavailable; terminal "
                         "receipt was not attributed to this caller"],
                        preflight_hash,
                    )
                response.update(captured)
                return response
            except Exception as exc:
                return self._held(
                    request_id, request_key,
                    [f"execution validation error: {type(exc).__name__}: {exc}"],
                    locals().get("preflight_hash"),
                )

    @staticmethod
    def _read_sink(sink):
        """Read at most the response limit while retaining the full byte count."""
        sink.seek(0, os.SEEK_END)
        byte_count = sink.tell()
        sink.seek(0)
        return sink.read(_OUTPUT_LIMIT), byte_count

    @staticmethod
    def _captured_fields(stdout_data, stderr_data, status_out, status_err):
        def bounded_bytes(captured):
            data, byte_count = captured
            text = data.decode("utf-8", errors="replace")
            encoded = text.encode("utf-8")
            if len(encoded) > _OUTPUT_LIMIT:
                text = encoded[:_OUTPUT_LIMIT].decode("utf-8", errors="ignore")
            return text, byte_count, byte_count > len(data) or len(encoded) > _OUTPUT_LIMIT

        def bounded_text(text):
            data = text.encode("utf-8", errors="replace")
            byte_count = len(data)
            if byte_count > _OUTPUT_LIMIT:
                text = data[:_OUTPUT_LIMIT].decode("utf-8", errors="ignore")
            return text, byte_count, byte_count > _OUTPUT_LIMIT

        stdout, stdout_bytes, stdout_truncated = bounded_bytes(stdout_data)
        stderr, stderr_bytes, stderr_truncated = bounded_bytes(stderr_data)
        status_stdout, status_stdout_bytes, status_stdout_truncated = bounded_text(status_out)
        status_stderr, status_stderr_bytes, status_stderr_truncated = bounded_text(status_err)
        return {
            "stdout": stdout, "stdout_bytes": stdout_bytes,
            "stdout_truncated": stdout_truncated,
            "stderr": stderr, "stderr_bytes": stderr_bytes,
            "stderr_truncated": stderr_truncated,
            "status_stdout": status_stdout,
            "status_stdout_bytes": status_stdout_bytes,
            "status_stdout_truncated": status_stdout_truncated,
            "status_stderr": status_stderr,
            "status_stderr_bytes": status_stderr_bytes,
            "status_stderr_truncated": status_stderr_truncated,
        }

    @staticmethod
    def _terminal_result(request_id, request_key, preflight_hash, decision,
                         attempt, cached):
        return {
            "request_id": request_id,
            "request_key": request_key,
            "preflight_hash": preflight_hash,
            "decision": decision,
            "state": "CACHED" if cached else "TERMINAL",
            "executed": bool(attempt.get("execution_started_hash")),
            "cached": cached,
            "exit_code": attempt.get("terminal_exit_code"),
            "terminal_kind": attempt.get("terminal_kind"),
            "terminal_error_type": attempt.get("terminal_error_type"),
            "terminal_error": attempt.get("terminal_error"),
            "reused": False,
            "reasons": [],
            "stdout": "", "stdout_bytes": 0, "stdout_truncated": False,
            "stderr": "", "stderr_bytes": 0, "stderr_truncated": False,
            "status_stdout": "", "status_stdout_bytes": 0,
            "status_stdout_truncated": False,
            "status_stderr": "", "status_stderr_bytes": 0,
            "status_stderr_truncated": False,
        }
