"""Portable release-hardening probe runner.

Runs the ten independently named contracts through the current interpreter and
emits one machine-readable JSON receipt. It performs no network or live actions.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBES = [
    (
        1,
        "version_identity",
        ["tests/test_version_consistency.py"],
    ),
    (
        2,
        "protected_delete_semantics",
        [
            "tests/test_gate_hardening.py::test_protected_delete_is_not_ordinary_confirmation",
            "tests/test_gate_hardening.py::test_protected_erasure_aliases_and_shell_boundaries_are_dry_only",
            "tests/test_gate_hardening.py::test_protected_non_erasing_actions_do_not_claim_dry_run",
            "tests/test_gate_hardening.py::test_protected_dry_run_can_be_disabled_only_by_policy",
        ],
    ),
    (
        3,
        "strict_policy_schema",
        [
            "tests/test_gate_hardening.py::test_policy_rejects_unknown_fields_with_exact_paths",
        ],
    ),
    (
        4,
        "offline_verifiable_ledger_export",
        ["tests/test_ledger.py::test_export_contains_self_sufficient_full_hash_chain"],
    ),
    (
        5,
        "cross_process_ledger_sink",
        [
            "tests/test_ledger.py::test_cross_process_flush_preserves_concurrent_buffered_record",
            "tests/test_ledger.py::test_atomic_merge_failure_preserves_active_and_inflight_bytes",
            "tests/test_ledger.py::test_flush_keeps_event_when_server_ack_has_no_valid_hash",
            "tests/test_ledger.py::test_record_replays_stale_and_active_generations_before_current",
            "tests/test_ledger.py::test_torn_buffer_line_is_quarantined_without_blocking_valid_events",
        ],
    ),
    (
        6,
        "mcp_exact_args",
        [
            "tests/test_gate_hardening.py::test_mcp_exact_args_enforce_max_args_through_preflight",
            "tests/test_gate_hardening.py::test_mcp_missing_or_non_vector_args_hold",
            "tests/test_gate_hardening.py::test_exec_binds_and_classifies_the_exact_argument_vector",
            "tests/test_gate_hardening.py::test_mcp_partial_server_state_fails_closed",
        ],
    ),
    (
        7,
        "hermes_authoritative_cwd",
        [
            "tests/test_gate_hardening.py::test_relative_mutation_without_authoritative_cwd_holds",
            "tests/test_gate_hardening.py::test_absolute_cwd_is_preserved_as_authoritative",
            "tests/test_gate_hook_bridge.py::test_bridge_preserves_authoritative_payload_cwd",
            "tests/test_gate_hook_bridge.py::test_bridge_prefers_terminal_workdir_over_session_cwd",
            "tests/test_gate_hook_bridge.py::test_bridge_blocks_non_authoritative_terminal_workdir",
            "tests/test_gate_hook_bridge.py::test_bridge_blocks_execute_code_instead_of_treating_missing_command_as_allow",
            "tests/test_gate_hook_bridge.py::test_bridge_blocks_malformed_payload_shapes",
        ],
    ),
    (
        8,
        "authoritative_db_identity",
        [
            "tests/test_db.py",
            "tests/test_gate_hardening.py::test_gate_db_identity_is_bound_to_result_and_ledger",
            "tests/test_gate_hardening.py::test_configured_missing_db_holds_without_creating_it",
            "tests/test_gate_hardening.py::test_caller_spoofed_context_identity_is_ignored",
            "tests/test_gate_hardening.py::test_mcp_preflight_recomputes_context_digest_after_canon_write",
            "tests/test_gate_hardening.py::test_mcp_configured_missing_db_holds_until_intentional_restart",
        ],
    ),
    (
        9,
        "structured_dry_run_result",
        [
            "tests/test_gate_hardening.py::test_cli_dry_run_is_single_structured_non_success_result",
        ],
    ),
    (
        10,
        "execution_lifecycle_receipts",
        [
            "tests/test_gate_hardening.py::test_execution_lifecycle_success_receipts",
            "tests/test_gate_hardening.py::test_execution_lifecycle_binds_materialized_snapshot_receipt",
            "tests/test_gate_hardening.py::test_execution_lifecycle_nonzero_and_exception_receipts",
            "tests/test_gate_hardening.py::test_snapshot_failure_records_terminal_failure_without_execution",
            "tests/test_gate_hardening.py::test_execution_rejects_unbound_or_non_executable_preflight",
            "tests/test_gate_hardening.py::test_terminal_receipt_failure_returns_ambiguous_side_effect_code",
        ],
    ),
]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", default="")
    args = parser.parse_args(argv)
    started = time.time()
    results = []
    for number, name, nodes in PROBES:
        command = [sys.executable, "-m", "pytest", "-q", *nodes]
        probe_started = time.time()
        completed = subprocess.run(
            command,
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        results.append({
            "probe": number,
            "name": name,
            "status": "PASS" if completed.returncode == 0 else "FAIL",
            "exit_code": completed.returncode,
            "duration_seconds": round(time.time() - probe_started, 3),
            "command": command,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        })
    receipt = {
        "schema": "continuityos-release-hardening-probes-v1",
        "root": str(ROOT),
        "python": sys.version,
        "platform": platform.platform(),
        "started_unix": started,
        "duration_seconds": round(time.time() - started, 3),
        "all_passed": all(item["status"] == "PASS" for item in results),
        "passed": sum(item["status"] == "PASS" for item in results),
        "total": len(results),
        "results": results,
    }
    rendered = json.dumps(receipt, ensure_ascii=False, indent=2)
    if args.json_out:
        output = Path(args.json_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0 if receipt["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
