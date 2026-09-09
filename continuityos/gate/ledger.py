"""Append-only audit ledger with a hash chain and single-attempt execution registry."""
from __future__ import annotations
import sqlite3, json, time, hashlib, os
from typing import Dict, Any, List

GENESIS = "0" * 64
HASH_SCHEME = "sha256-prev-kind-ts6-payload-v1"
ATTEMPT_PHASES = {"CLAIMED", "ATTEMPT_STARTED", "TERMINAL"}

class Ledger:
    def __init__(self, path: str = "continuity_ledger.db"):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.con = sqlite3.connect(path, timeout=30.0)
        self.con.execute("PRAGMA busy_timeout=30000")
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=FULL")
        self.con.row_factory = sqlite3.Row
        self.con.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT,
            payload TEXT, prev_hash TEXT, hash TEXT)""")
        self.con.execute("""CREATE TABLE IF NOT EXISTS execution_attempts(
            preflight_hash TEXT PRIMARY KEY,
            binding_sha256 TEXT NOT NULL,
            phase TEXT NOT NULL CHECK(phase IN ('CLAIMED','ATTEMPT_STARTED','TERMINAL')),
            claim_hash TEXT NOT NULL,
            execution_started_hash TEXT,
            terminal_kind TEXT,
            terminal_hash TEXT,
            terminal_exit_code INTEGER,
            terminal_error_type TEXT,
            terminal_error TEXT,
            created_ts REAL NOT NULL,
            updated_ts REAL NOT NULL)""")
        self.con.commit()

    def _last_hash(self) -> str:
        row = self.con.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        return row["hash"] if row else GENESIS

    def _append_event_in_transaction(self, kind: str, payload: Dict[str, Any]) -> str:
        body = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        ts = time.time()
        prev = self._last_hash()
        digest = hashlib.sha256(
            (prev + kind + ("%.6f" % ts) + body).encode("utf-8")
        ).hexdigest()
        self.con.execute(
            "INSERT INTO events(ts,kind,payload,prev_hash,hash) VALUES(?,?,?,?,?)",
            (ts, kind, body, prev, digest),
        )
        return digest

    def append(self, kind: str, payload: Dict[str, Any]) -> str:
        try:
            self.con.execute("BEGIN IMMEDIATE")
            digest = self._append_event_in_transaction(kind, payload)
            self.con.commit()
            return digest
        except Exception:
            self.con.rollback()
            raise

    def verify(self) -> Dict[str, Any]:
        prev = GENESIS; count = 0
        for row in self.con.execute("SELECT * FROM events ORDER BY id"):
            digest = hashlib.sha256(
                (prev + row["kind"] + ("%.6f" % row["ts"]) + row["payload"]).encode("utf-8")
            ).hexdigest()
            if digest != row["hash"] or row["prev_hash"] != prev:
                return {"ok": False, "broken_at": row["id"], "verified": count}
            prev = row["hash"]; count += 1
        return {"ok": True, "verified": count}

    def export(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self.con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._event_dict(row) for row in rows]

    @staticmethod
    def _event_dict(row) -> Dict[str, Any]:
        return {
            "id": row["id"], "ts": row["ts"], "ts_text": "%.6f" % row["ts"],
            "kind": row["kind"], "payload": json.loads(row["payload"]),
            "payload_json": row["payload"], "prev_hash": row["prev_hash"],
            "hash": row["hash"], "hash_scheme": HASH_SCHEME,
        }

    def event(self, event_hash: str):
        row = self.con.execute(
            "SELECT * FROM events WHERE hash=? LIMIT 1", (event_hash,)
        ).fetchone()
        return self._event_dict(row) if row is not None else None

    def _require_preflight_for_claim(
        self, preflight_hash: str, expected_action: Dict[str, Any],
        expected_rollback_plan: Dict[str, Any], expected_decision: str,
    ) -> None:
        verification = self.verify()
        if not verification.get("ok"):
            raise ValueError("execution ledger failed hash-chain verification")
        event = self.event(preflight_hash)
        if event is None or event.get("kind") != "preflight":
            raise ValueError("preflight hash does not identify a ledger preflight event")
        payload = event["payload"]
        if payload.get("action") != expected_action:
            raise ValueError("typed action differs from ledger-bound preflight action")
        if payload.get("rollback_plan") != expected_rollback_plan:
            raise ValueError("rollback plan differs from ledger-bound preflight plan")
        if payload.get("decision") != expected_decision:
            raise ValueError("decision differs from ledger-bound preflight decision")
        if expected_decision not in ("ALLOW", "WARN", "REQUIRE_CONFIRMATION"):
            raise ValueError("ledger-bound decision is not executable")
        if expected_decision == "REQUIRE_CONFIRMATION":
            approved = False
            for row in self.con.execute("SELECT payload FROM events WHERE kind='override' ORDER BY id"):
                try:
                    override = json.loads(row["payload"])
                except (TypeError, json.JSONDecodeError):
                    continue
                if override.get("preflight_hash") == preflight_hash and override.get("by") == "human":
                    approved = True; break
            if not approved:
                raise ValueError("confirmation-required preflight has no human override receipt")

    def _attempt_row(self, preflight_hash: str):
        return self.con.execute(
            "SELECT * FROM execution_attempts WHERE preflight_hash=?",
            (preflight_hash,),
        ).fetchone()

    def _validate_attempt_row(self, row) -> Dict[str, Any]:
        if row is None:
            raise ValueError("execution attempt row missing")
        data = dict(row)
        if data["phase"] not in ATTEMPT_PHASES:
            raise ValueError("execution attempt has invalid phase")
        claim = self.event(data["claim_hash"])
        if claim is None or claim.get("kind") != "attempt_claimed":
            raise ValueError("execution attempt claim pointer is invalid")
        claim_payload = claim["payload"]
        if claim_payload.get("phase") != "CLAIMED":
            raise ValueError("attempt_claimed event payload phase is not CLAIMED")
        if claim_payload.get("preflight_hash") != data["preflight_hash"]:
            raise ValueError("execution attempt claim points at another preflight")
        if claim_payload.get("binding_sha256") != data["binding_sha256"]:
            raise ValueError("execution attempt claim binding mismatch")
        started_hash = data["execution_started_hash"]
        terminal_hash = data["terminal_hash"]
        if data["phase"] == "CLAIMED" and (started_hash or terminal_hash):
            raise ValueError("CLAIMED attempt has impossible receipt pointers")
        if data["phase"] == "ATTEMPT_STARTED" and (not started_hash or terminal_hash):
            raise ValueError("ATTEMPT_STARTED attempt has impossible receipt pointers")
        if started_hash:
            started = self.event(started_hash)
            if started is None or started.get("kind") != "execution_started":
                raise ValueError("execution_started pointer is invalid")
            if started["payload"].get("preflight_hash") != data["preflight_hash"]:
                raise ValueError("execution_started points at another preflight")
        if data["phase"] in ("CLAIMED", "ATTEMPT_STARTED"):
            if data.get("terminal_kind") is not None or data.get("terminal_hash") is not None or data.get("terminal_exit_code") is not None or data.get("terminal_error_type") is not None or data.get("terminal_error") is not None:
                raise ValueError("CLAIMED/ATTEMPT_STARTED has terminal fields set")
        if data["phase"] == "TERMINAL":
            if data["terminal_kind"] not in ("execution_completed", "execution_failed"):
                raise ValueError("TERMINAL has invalid terminal_kind")
            terminal = self.event(data["terminal_hash"])
            if terminal is None or terminal.get("kind") != data["terminal_kind"]:
                raise ValueError("terminal receipt pointer is invalid")
            payload = terminal["payload"]
            if payload.get("preflight_hash") != data["preflight_hash"]:
                raise ValueError("terminal receipt points at another preflight")
            if payload.get("exit_code") != data["terminal_exit_code"]:
                raise ValueError("terminal exit metadata mismatch")
            if payload.get("error_type") != data["terminal_error_type"]:
                raise ValueError("terminal error type metadata mismatch")
            if payload.get("error") != data["terminal_error"]:
                raise ValueError("terminal error metadata mismatch")
            if started_hash:
                started = self.event(started_hash)
                if started is None or started.get("kind") != "execution_started":
                    raise ValueError("execution_started pointer is invalid")
                if started["payload"].get("preflight_hash") != data["preflight_hash"]:
                    raise ValueError("execution_started points at another preflight")
                if payload.get("execution_attempted") is not True:
                    raise ValueError("started_hash exists but attempted not true")
                if payload.get("execution_started_hash") != started_hash:
                    raise ValueError("execution_started_hash mismatch with registry")
                if data["terminal_kind"] == "execution_completed":
                    if payload.get("executed") is not True:
                        raise ValueError("execution_completed requires executed True")
                    if type(payload.get("exit_code")) is not int or payload.get("exit_code") != 0:
                        raise ValueError("execution_completed requires exit_code int 0")
                elif data["terminal_kind"] == "execution_failed":
                    if payload.get("executed") is True:
                        if type(payload.get("exit_code")) is not int or payload.get("exit_code") == 0:
                            raise ValueError("execution_failed executed=True requires int exit_code != 0")
                    elif payload.get("executed") is False:
                        if payload.get("exit_code") is not None:
                            raise ValueError("execution_failed executed=False requires exit_code None")
                    else:
                        raise ValueError("execution_failed requires executed True or False")
                else:
                    raise ValueError("invalid terminal_kind for TERMINAL")
            else:
                if data["terminal_kind"] != "execution_failed":
                    raise ValueError("no started_hash requires execution_failed")
                if payload.get("execution_attempted") is not False:
                    raise ValueError("no started_hash requires execution_attempted false")
                if payload.get("executed") is not False:
                    raise ValueError("no started_hash requires executed false")
                if payload.get("execution_started_hash") is not None:
                    raise ValueError("no started_hash requires no execution_started_hash in payload")
                if payload.get("exit_code") is not None:
                    raise ValueError("no started_hash requires exit_code None")
        return data

    def claim_execution_attempt(
        self, *, preflight_hash: str, binding_sha256: str,
        expected_action: Dict[str, Any], expected_rollback_plan: Dict[str, Any],
        expected_decision: str,
    ) -> Dict[str, Any]:
        try:
            self.con.execute("BEGIN IMMEDIATE")
            self._require_preflight_for_claim(
                preflight_hash, expected_action, expected_rollback_plan, expected_decision
            )
            row = self._attempt_row(preflight_hash)
            if row is not None:
                data = self._validate_attempt_row(row)
                if data["binding_sha256"] != binding_sha256:
                    raise ValueError("execution attempt binding conflict")
                self.con.commit()
                return {"status": data["phase"], **data}
            for claim_row in self.con.execute("SELECT payload FROM events WHERE kind='attempt_claimed'"):
                try:
                    p = json.loads(claim_row["payload"])
                    if not isinstance(p, dict):
                        raise ValueError("malformed attempt_claimed payload")
                    pf = p.get("preflight_hash")
                    bd = p.get("binding_sha256")
                    if (
                        not isinstance(pf, str)
                        or len(pf) != 64
                        or not all(c in "0123456789abcdef" for c in pf)
                        or not isinstance(bd, str)
                        or len(bd) != 64
                        or not all(c in "0123456789abcdef" for c in bd)
                        or p.get("phase") != "CLAIMED"
                    ):
                        raise ValueError("malformed attempt_claimed payload")
                except (TypeError, json.JSONDecodeError) as e:
                    raise ValueError("malformed attempt_claimed payload") from e
                if pf == preflight_hash:
                    raise ValueError("orphaned prior claim found with missing registry state")
            claim_hash = self._append_event_in_transaction("attempt_claimed", {
                "preflight_hash": preflight_hash,
                "binding_sha256": binding_sha256,
                "phase": "CLAIMED",
            })
            now = time.time()
            self.con.execute(
                """INSERT INTO execution_attempts(
                    preflight_hash,binding_sha256,phase,claim_hash,created_ts,updated_ts
                ) VALUES(?,?,?,?,?,?)""",
                (preflight_hash, binding_sha256, "CLAIMED", claim_hash, now, now),
            )
            self.con.commit()
            return {"status": "CLAIMED_NEW", "preflight_hash": preflight_hash,
                    "binding_sha256": binding_sha256, "claim_hash": claim_hash}
        except Exception:
            self.con.rollback()
            raise

    def start_execution_attempt(
        self, *, preflight_hash: str, binding_sha256: str,
        payload: Dict[str, Any],
    ) -> str:
        try:
            self.con.execute("BEGIN IMMEDIATE")
            data = self._validate_attempt_row(self._attempt_row(preflight_hash))
            if data["binding_sha256"] != binding_sha256:
                raise ValueError("execution attempt binding conflict")
            if data["phase"] != "CLAIMED":
                raise ValueError(f"execution attempt is {data['phase']}, not CLAIMED")
            preflight_check = self.event(preflight_hash)
            # preflight-hash validation kept before event append (already validated above)
            if payload.get('preflight_hash') != preflight_hash:
                raise ValueError("preflight hash mismatch on start")
            started_hash = self._append_event_in_transaction("execution_started", payload)
            self.con.execute(
                """UPDATE execution_attempts
                   SET phase='ATTEMPT_STARTED', execution_started_hash=?, updated_ts=?
                   WHERE preflight_hash=? AND phase='CLAIMED'""",
                (started_hash, time.time(), preflight_hash),
            )
            if self.con.execute("SELECT changes()").fetchone()[0] != 1:
                raise RuntimeError("execution attempt start CAS failed")
            self.con.commit()
            return started_hash
        except Exception:
            self.con.rollback()
            raise

    def finish_execution_attempt(
        self, *, preflight_hash: str, binding_sha256: str,
        terminal_kind: str, payload: Dict[str, Any],
    ) -> str:
        if terminal_kind not in ("execution_completed", "execution_failed"):
            raise ValueError("invalid terminal execution kind")
        try:
            self.con.execute("BEGIN IMMEDIATE")
            data = self._validate_attempt_row(self._attempt_row(preflight_hash))
            if data["binding_sha256"] != binding_sha256:
                raise ValueError("execution attempt binding conflict")
            registry_started_hash = data.get("execution_started_hash")
            if data["phase"] == "CLAIMED":
                if terminal_kind != "execution_failed":
                    raise ValueError("invalid CLAIMED terminal kind: execution_failed required")
                if payload.get("execution_started_hash") is not None:
                    raise ValueError("execution_started_hash must be None for CLAIMED")
                if payload.get("execution_attempted") is not False or payload.get("executed") is not False or registry_started_hash is not None or payload.get("exit_code") is not None:
                    raise ValueError("invalid CLAIMED terminal shape")
            if data["phase"] == "ATTEMPT_STARTED":
                if payload.get("execution_attempted") is not True:
                    raise ValueError("ATTEMPT_STARTED requires execution_attempted True")
                if payload.get("execution_started_hash") != registry_started_hash:
                    raise ValueError("execution_started_hash mismatch")
                if terminal_kind == "execution_completed":
                    if payload.get("executed") is not True or type(payload.get("exit_code")) is not int or payload.get("exit_code") != 0:
                        raise ValueError("execution_completed requires executed=True, int exit_code 0")
                elif terminal_kind == "execution_failed":
                    if payload.get("executed") is True:
                        if type(payload.get("exit_code")) is not int or payload.get("exit_code") == 0:
                            raise ValueError("execution_failed executed=True requires int exit_code != 0")
                    elif payload.get("executed") is False:
                        if payload.get("exit_code") is not None:
                            raise ValueError("execution_failed executed=False requires exit_code None")
                    else:
                        raise ValueError("execution_failed requires executed True or False")
                else:
                    raise ValueError("invalid terminal_kind for TERMINAL")
            elif data["phase"] != "CLAIMED":
                raise ValueError(f"execution attempt is {data['phase']}, not finishable")
            if payload.get('preflight_hash') != preflight_hash:
                raise ValueError("preflight hash mismatch on finish")
            # preflight-hash validation before terminal event append (already validated)
            terminal_hash = self._append_event_in_transaction(terminal_kind, payload)
            self.con.execute(
                """UPDATE execution_attempts SET phase='TERMINAL', terminal_kind=?,
                   terminal_hash=?, terminal_exit_code=?, terminal_error_type=?, terminal_error=?,
                   updated_ts=? WHERE preflight_hash=? AND phase=?""",
                (terminal_kind, terminal_hash, payload.get("exit_code"), payload.get("error_type"),
                 payload.get("error"), time.time(), preflight_hash, data["phase"]),
            )
            if self.con.execute("SELECT changes()").fetchone()[0] != 1:
                raise RuntimeError("execution attempt terminal CAS failed")
            self.con.commit()
            return terminal_hash
        except Exception:
            self.con.rollback()
            raise

    def close(self) -> None:
        self.con.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
