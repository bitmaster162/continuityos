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
from continuityos.gate.witness import WitnessAuthority


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
    def __init__(self, registry_path=None, ledger_path=None, db=None, *,
                 policy_snapshot=None, context_error="", witness_path=None,
                 monotonic_anchor=None):
        self.registry_path = registry_path or os.path.expanduser(
            "~/.continuityos/gate_broker.db"
        )
        self.ledger_path = ledger_path or cli.LEDGER
        self.witness = None
        if witness_path is not None:
            self.witness = WitnessAuthority(
                witness_path, self.ledger_path, self.registry_path
            )
            self.witness.bootstrap()
        self.monotonic_anchor = monotonic_anchor
        if self.monotonic_anchor is not None and self.witness is None:
            raise ValueError("R15 monotonic anchor requires the R14 witness authority")
        self.db = db
        # Product adapters may inject the one policy snapshot loaded at their
        # startup boundary.  ``None`` preserves the R12 discovery/load path.
        self._policy_snapshot = policy_snapshot
        self._context_error = context_error
        os.makedirs(
            os.path.dirname(os.path.abspath(self.registry_path)) or ".",
            exist_ok=True,
        )
        registry_existed = os.path.exists(self.registry_path)
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
            if self.witness is not None:
                doc = self.witness.read()
                con.execute("""CREATE TABLE IF NOT EXISTS governance_metadata(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    state_id TEXT NOT NULL)""")
                row = con.execute(
                    "SELECT state_id FROM governance_metadata WHERE singleton=1"
                ).fetchone()
                if row is None:
                    if registry_existed and not getattr(
                        self.witness, "bootstrap_recovery", False
                    ):
                        raise ValueError(
                            "existing broker registry has no R14 state_id; offline migration required"
                        )
                    con.execute(
                        "INSERT INTO governance_metadata(singleton,state_id) VALUES(1,?)",
                        (doc["state_id"],),
                    )
                elif row[0] != doc["state_id"]:
                    raise ValueError("broker registry state_id does not match witness")
                con.execute("""CREATE TRIGGER IF NOT EXISTS governance_metadata_no_update
                    BEFORE UPDATE ON governance_metadata BEGIN
                    SELECT RAISE(ABORT, 'governance state_id is immutable'); END""")
                con.execute("""CREATE TRIGGER IF NOT EXISTS governance_metadata_no_delete
                    BEFORE DELETE ON governance_metadata BEGIN
                    SELECT RAISE(ABORT, 'governance state_id is immutable'); END""")
            con.commit()
        self._lock = threading.RLock()
        if self.witness is not None:
            with self._ledger() as ledger:
                self._require_monotonic_runtime(ledger)

    def _ledger(self):
        if self.witness is None:
            return Ledger(self.ledger_path)
        return Ledger(self.ledger_path, witness=self.witness)

    @staticmethod
    def _r15_activated(ledger):
        return ledger.con.execute(
            "SELECT 1 FROM events WHERE kind='monotonic_anchor' LIMIT 1"
        ).fetchone() is not None

    def _require_monotonic_runtime(self, ledger):
        if self._r15_activated(ledger) and self.monotonic_anchor is None:
            raise ValueError(
                "R15-activated governance state requires the monotonic anchor"
            )
        if self.monotonic_anchor is not None:
            self.monotonic_anchor.require_runtime_consistency(ledger)

    def _validate_registry_state(self):
        if self.witness is None:
            return
        doc = self.witness.read()
        with sqlite3.connect(self.registry_path, timeout=30) as con:
            row = con.execute(
                "SELECT state_id FROM governance_metadata WHERE singleton=1"
            ).fetchone()
        if row is None or row[0] != doc["state_id"]:
            raise ValueError("broker registry state_id does not match witness")

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
        if self._policy_snapshot is None:
            try:
                policy = cli.load_policy(cli.discover_policy(cli.HOME))
            except (cli.PolicyError, OSError) as exc:
                policy = cli.default_policy()
                spec.meta["policy_error"] = f"{type(exc).__name__}: {exc}"
        else:
            policy = self._policy_snapshot
        if self._context_error:
            context, context_error = None, self._context_error
        else:
            context, context_error, _context_identity = cli._context(self.db)
        if context_error:
            spec.meta["context_error"] = context_error
        return policy, context

    def _preflight_exec(self, request_id, argv, cwd, paths=None):
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
                            with self._ledger() as ledger:
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
                    with self._ledger() as ledger:
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

    def _execute_preflight(self, request_id):
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

                with self._ledger() as ledger:
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
                    if (
                        attempt is not None
                        and attempt["phase"] == "TERMINAL"
                        and self.monotonic_anchor is not None
                    ):
                        self.monotonic_anchor.require_terminal_receipt(
                            ledger, preflight_hash=preflight_hash,
                            binding_sha256=expected_binding, attempt=attempt,
                        )

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
                                witness_authority=self.witness,
                                monotonic_anchor=self.monotonic_anchor,
                            )
                    stdout_data = self._read_sink(child_out)
                    stderr_data = self._read_sink(child_err)

                with self._ledger() as ledger:
                    if not ledger.verify().get("ok"):
                        return self._held(request_id, request_key, ["ledger hash chain verification failed after execution"], preflight_hash)
                    row = ledger._attempt_row(preflight_hash)
                    attempt = None if row is None else ledger._validate_attempt_row(row)
                    if (
                        attempt is not None
                        and attempt["phase"] == "TERMINAL"
                        and self.monotonic_anchor is not None
                    ):
                        self.monotonic_anchor.require_terminal_receipt(
                            ledger, preflight_hash=preflight_hash,
                            binding_sha256=expected_binding, attempt=attempt,
                        )
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

    def preflight_exec(self, request_id, argv, cwd, paths=None):
        if self.witness is None:
            return self._preflight_exec(request_id, argv, cwd, paths)
        with self.witness.locked():
            try:
                self._validate_registry_state()
                with self._ledger() as ledger:
                    self._require_monotonic_runtime(ledger)
                return self._preflight_exec(request_id, argv, cwd, paths)
            except Exception as exc:
                return self._held(
                    request_id, self._key(request_id) if isinstance(request_id, str) else None,
                    [f"witness validation error: {type(exc).__name__}: {exc}"],
                )

    def execute_preflight(self, request_id):
        if self.witness is None:
            return self._execute_preflight(request_id)
        with self.witness.locked():
            try:
                self._validate_registry_state()
                with self._ledger() as ledger:
                    self._require_monotonic_runtime(ledger)
                return self._execute_preflight(request_id)
            except Exception as exc:
                return self._held(
                    request_id, self._key(request_id) if isinstance(request_id, str) else None,
                    [f"witness validation error: {type(exc).__name__}: {exc}"],
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
