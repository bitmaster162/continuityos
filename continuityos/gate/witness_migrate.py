"""Explicit offline R13/pre-R14 governance-state migration to R14 witness mode.

This utility is deliberately not imported by product startup or exposed through
MCP.  Stop all writers before running it.
"""
from __future__ import annotations

import argparse
import os
import secrets
import sqlite3

from continuityos.gate.ledger import Ledger
from continuityos.gate.witness import (
    WitnessAuthority, WitnessError, _canonical, _document, _is_state_id,
    durable_atomic_write,
)


def _metadata(con):
    try:
        row = con.execute(
            "SELECT state_id FROM governance_metadata WHERE singleton=1"
        ).fetchone()
    except sqlite3.Error:
        return None
    return row[0] if row else None


def _install_metadata(con, state_id):
    con.execute("""CREATE TABLE IF NOT EXISTS governance_metadata(
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), state_id TEXT NOT NULL)""")
    row = con.execute(
        "SELECT state_id FROM governance_metadata WHERE singleton=1"
    ).fetchone()
    if row is None:
        con.execute(
            "INSERT INTO governance_metadata(singleton,state_id) VALUES(1,?)",
            (state_id,),
        )
    elif row[0] != state_id:
        raise WitnessError("existing migration state_id mismatch")
    con.execute("""CREATE TRIGGER IF NOT EXISTS governance_metadata_no_update
        BEFORE UPDATE ON governance_metadata BEGIN
        SELECT RAISE(ABORT, 'governance state_id is immutable'); END""")
    con.execute("""CREATE TRIGGER IF NOT EXISTS governance_metadata_no_delete
        BEFORE DELETE ON governance_metadata BEGIN
        SELECT RAISE(ABORT, 'governance state_id is immutable'); END""")


def _commit_metadata(con, state_id):
    con.execute("BEGIN IMMEDIATE")
    try:
        _install_metadata(con, state_id)
        con.commit()
    except Exception:
        con.rollback()
        raise


def _migration_state_id(ledger_id, registry_id):
    present = [value for value in (ledger_id, registry_id) if value is not None]
    if any(not _is_state_id(value) for value in present):
        raise WitnessError("prior migration state_id is invalid")
    if len(set(present)) > 1:
        raise WitnessError("partial or mismatched prior migration metadata")
    return present[0] if present else secrets.token_hex(32)


def _validate_execution_attempt_bindings(ledger):
    """Recompute each runtime binding from its exact ledger preflight."""
    from continuityos.gate import cli as gate_cli

    for row in ledger.con.execute(
        "SELECT * FROM execution_attempts ORDER BY preflight_hash"
    ):
        data = ledger._validate_attempt_row(row)
        preflight_hash = data["preflight_hash"]
        event = ledger.event(preflight_hash)
        if event is None or event.get("kind") != "preflight":
            raise WitnessError(
                "legacy execution attempt does not reference an exact preflight"
            )
        payload = event.get("payload")
        action = payload.get("action") if isinstance(payload, dict) else None
        if not isinstance(action, dict):
            raise WitnessError("legacy execution attempt preflight action is malformed")
        mode = action.get("tool")
        argv = action.get("args")
        command = action.get("command")
        cwd = action.get("cwd")
        if (
            mode not in ("exec", "shell")
            or not isinstance(command, str)
            or not isinstance(cwd, str) or not cwd
            or not isinstance(argv, list)
            or not all(isinstance(value, str) for value in argv)
        ):
            raise WitnessError("legacy execution attempt preflight binding is malformed")
        result = {"ledger_hash": preflight_hash, "action": action}
        expected = gate_cli._execution_binding_sha256(
            command, mode, result, list(argv), execution_cwd=cwd
        )
        if data.get("binding_sha256") != expected:
            raise WitnessError(
                "legacy execution attempt binding differs from exact preflight"
            )


def _require_exact_witness_frontier(authority, ledger):
    doc = authority.read()
    frontier = ledger.frontier()
    if (
        doc["event_count"] != frontier["event_count"]
        or doc["event_hash"] != frontier["event_hash"]
    ):
        raise WitnessError(
            "existing migration witness does not equal current ledger frontier"
        )
    return doc, frontier


def migrate(ledger_path, registry_path, witness_path):
    authority = WitnessAuthority(witness_path, ledger_path, registry_path)
    ledger_path = authority.ledger_path
    registry_path = authority.registry_path
    witness_path = authority.path
    if not os.path.isfile(ledger_path) or not os.path.isfile(registry_path):
        raise WitnessError("offline migration requires existing ledger and registry")

    with authority.locked(), Ledger(ledger_path) as ledger, sqlite3.connect(
        registry_path, timeout=30
    ) as registry:
        verification = ledger.verify()
        if not verification.get("ok"):
            raise WitnessError("legacy ledger hash chain is invalid")
        try:
            ledger.validate_execution_lifecycle()
        except (KeyError, TypeError, ValueError, sqlite3.Error) as exc:
            raise WitnessError("legacy execution lifecycle is invalid") from exc
        _validate_execution_attempt_bindings(ledger)
        try:
            mappings = registry.execute(
                "SELECT request_key,action_sha256,preflight_hash "
                "FROM broker_requests ORDER BY request_key,preflight_hash"
            ).fetchall()
        except sqlite3.Error as exc:
            raise WitnessError("legacy broker registry schema is invalid") from exc
        from continuityos.gate.broker import GateBroker
        request_keys = set()
        preflight_hashes = set()
        for mapping in mappings:
            if len(mapping) != 3:
                raise WitnessError("legacy broker registry mapping is malformed")
            request_key, action_sha256, preflight_hash = mapping
            if (
                not GateBroker._is_hash(request_key)
                or request_key == "0" * 64
                or not GateBroker._is_hash(action_sha256)
                or action_sha256 == "0" * 64
                or not GateBroker._is_hash(preflight_hash)
                or preflight_hash == "0" * 64
            ):
                raise WitnessError("legacy broker registry mapping is malformed")
            if request_key in request_keys or preflight_hash in preflight_hashes:
                raise WitnessError("legacy broker registry mapping is duplicated")
            request_keys.add(request_key)
            preflight_hashes.add(preflight_hash)
            event = ledger.event(preflight_hash)
            if event is None or event.get("kind") != "preflight":
                raise WitnessError(
                    "legacy broker registry mapping points outside verified preflights"
                )
            _decision, error = GateBroker._validated_event(
                event, request_key, action_sha256
            )
            if error is not None:
                raise WitnessError(
                    f"legacy broker registry mapping is invalid: {error}"
                )

        ledger_id = _metadata(ledger.con)
        registry_id = _metadata(registry)
        if os.path.exists(witness_path):
            doc, frontier = _require_exact_witness_frontier(authority, ledger)
            state_id = doc["state_id"]
            for existing in (ledger_id, registry_id):
                if existing is not None and existing != state_id:
                    raise WitnessError(
                        "existing migration metadata does not match witness state_id"
                    )
        else:
            state_id = _migration_state_id(ledger_id, registry_id)
            frontier = ledger.frontier()
            durable_atomic_write(
                witness_path,
                _canonical(_document(
                    state_id, frontier["event_count"], frontier["event_hash"]
                )),
            )
            doc, checked = _require_exact_witness_frontier(authority, ledger)
            if checked != frontier or doc["state_id"] != state_id:
                raise WitnessError("migration witness verification failed")

        # The witness is authoritative before either database metadata commit.
        # A crash after any following line therefore remains fail-closed and a
        # rerun can complete the exact same state_id/frontier deterministically.
        if ledger_id != state_id:
            _commit_metadata(ledger.con, state_id)
        if registry_id != state_id:
            _commit_metadata(registry, state_id)

        if _metadata(ledger.con) != state_id or _metadata(registry) != state_id:
            raise WitnessError("migration metadata completion failed")
        doc, frontier = _require_exact_witness_frontier(authority, ledger)
        if ledger.state_id() != doc["state_id"]:
            raise WitnessError("migrated ledger state_id does not match witness")
        return {
            "state_id": state_id,
            "event_count": frontier["event_count"],
            "event_hash": frontier["event_hash"],
            "witness_path": witness_path,
        }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline one-time migration of valid R13 state to R14 witness mode"
    )
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--witness", required=True)
    args = parser.parse_args(argv)
    result = migrate(args.ledger, args.registry, args.witness)
    print("migrated state_id=%s events=%d witness=%s" % (
        result["state_id"], result["event_count"], result["witness_path"]
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
