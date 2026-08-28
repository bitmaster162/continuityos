#!/usr/bin/env python3
"""Frozen real-project CurrentTruthBench for the deterministic state resolver.

The fixtures are offline snapshots of stale-projection classes observed in the
ContinuityOS repository.  They test precedence logic; they do not replace a
fresh provider readback for any live decision.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from continuityos.gate.state_resolution import CANDIDATE_SCHEMA, resolve_state
from bench.sealing import (
    build_manifest,
    canonical_sha256,
    sha256_file,
    write_json,
)


def _observation_sha(observation: dict[str, Any]) -> str:
    return canonical_sha256(observation)


def _candidate(
    *,
    subject: str,
    observation: dict[str, Any],
    kind: str,
    status: str,
    observed_at_utc: str,
    current_observation: bool,
) -> dict[str, Any]:
    return {
        "schema": CANDIDATE_SCHEMA,
        "subject": subject,
        "artifact_id": f"{observation['source']}:{observation['object_id']}",
        "kind": kind,
        "status": status,
        "observed_at_utc": observed_at_utc,
        "production_qualified": False,
        "evidence_debt": False,
        "current_observation": current_observation,
        "artifact_sha256": _observation_sha(observation),
    }


def fixtures() -> list[dict[str, Any]]:
    issue111 = {
        "source": "github_issue",
        "object_id": "111",
        "repository": "bitmaster162/continuityos",
        "state": "open",
        "created_at": "2026-08-22T00:54:43Z",
        "updated_at": "2026-08-22T00:54:43Z",
        "stale_claim": "Causal Spine remains an implementation task",
    }
    pr115 = {
        "source": "github_pr",
        "object_id": "115",
        "repository": "bitmaster162/continuityos",
        "state": "closed",
        "merged": True,
        "merged_at": "2026-08-22T06:13:21Z",
        "merge_commit_sha": "e499f54cc658604e29464fefc5694f68532cef75",
    }
    issue114 = {
        "source": "github_issue",
        "object_id": "114",
        "repository": "bitmaster162/continuityos",
        "state": "open",
        "updated_at": "2026-08-26T10:25:45Z",
        "stale_claim": "PR #115 remains active P0 CORE and under independent re-review",
    }
    build_gate = {
        "source": "repository_file",
        "object_id": "BUILD_GATE_STATUS.md@fff3ecc2f83238d909eadf2f6e73eba33cca93d3",
        "repository": "bitmaster162/continuityos",
        "document_date": "2026-07-12",
        "historical_head": "fff3ecc2f83238d909eadf2f6e73eba33cca93d3",
        "claim_class": "historical measured status",
    }
    current_master = {
        "source": "github_branch_readback",
        "object_id": "master",
        "repository": "bitmaster162/continuityos",
        "head": "fa0542d6b696cd525b35319c568433b1dc2a05b2",
        "tree": "54dd850f283973beee7e3eebf51399a7c50c6e07",
        "commit_time": "2026-08-25T18:17:35Z",
        "protected": True,
    }

    return [
        {
            "case_id": "issue-111-stale-open-vs-pr-115-merged",
            "evidence": [issue111, pr115],
            "candidates": [
                _candidate(
                    subject="causal-spine-115",
                    observation=issue111,
                    kind="TEMPLATE",
                    status="OPEN",
                    observed_at_utc=issue111["updated_at"],
                    current_observation=False,
                ),
                _candidate(
                    subject="causal-spine-115",
                    observation=pr115,
                    kind="PROVIDER_READBACK",
                    status="PASS",
                    observed_at_utc=pr115["merged_at"],
                    current_observation=True,
                ),
            ],
            "expected": {
                "terminal": "STATE_RESOLUTION_PASS",
                "selected_kind": "PROVIDER_READBACK",
                "selected_status": "PASS",
            },
        },
        {
            "case_id": "issue-114-stale-sequencing-vs-pr-115-merged",
            "evidence": [issue114, pr115],
            "candidates": [
                _candidate(
                    subject="fleet-sequencing",
                    observation=issue114,
                    kind="TEMPLATE",
                    status="OPEN",
                    observed_at_utc=issue114["updated_at"],
                    current_observation=False,
                ),
                _candidate(
                    subject="fleet-sequencing",
                    observation=pr115,
                    kind="PROVIDER_READBACK",
                    status="PASS",
                    observed_at_utc=pr115["merged_at"],
                    current_observation=True,
                ),
            ],
            "expected": {
                "terminal": "STATE_RESOLUTION_PASS",
                "selected_kind": "PROVIDER_READBACK",
                "selected_status": "PASS",
            },
        },
        {
            "case_id": "historical-build-status-vs-current-master-readback",
            "evidence": [build_gate, current_master],
            "candidates": [
                _candidate(
                    subject="repository-current-state",
                    observation=build_gate,
                    kind="AUDIT",
                    status="HOLD",
                    observed_at_utc="2026-07-12T00:00:00Z",
                    current_observation=False,
                ),
                _candidate(
                    subject="repository-current-state",
                    observation=current_master,
                    kind="PROVIDER_READBACK",
                    status="PASS",
                    observed_at_utc=current_master["commit_time"],
                    current_observation=True,
                ),
            ],
            "expected": {
                "terminal": "STATE_RESOLUTION_PASS",
                "selected_kind": "PROVIDER_READBACK",
                "selected_status": "PASS",
            },
        },
        {
            "case_id": "fresh-provider-contradiction-blocks-older-human-pass",
            "evidence": [],
            "candidates": [
                {
                    "schema": CANDIDATE_SCHEMA,
                    "subject": "effect-gate",
                    "artifact_id": "human:decision-1",
                    "kind": "HUMAN_DECISION",
                    "status": "PASS",
                    "observed_at_utc": "2026-08-22T06:00:00Z",
                    "production_qualified": False,
                    "evidence_debt": False,
                    "current_observation": False,
                    "artifact_sha256": "a" * 64,
                },
                {
                    "schema": CANDIDATE_SCHEMA,
                    "subject": "effect-gate",
                    "artifact_id": "provider:readback-2",
                    "kind": "PROVIDER_READBACK",
                    "status": "REJECT",
                    "observed_at_utc": "2026-08-22T07:00:00Z",
                    "production_qualified": False,
                    "evidence_debt": False,
                    "current_observation": True,
                    "artifact_sha256": "b" * 64,
                },
            ],
            "expected": {
                "terminal": "STATE_RESOLUTION_HOLD",
                "reason": "FRESH_CURRENT_CONTRADICTION",
            },
        },
        {
            "case_id": "equal-provider-authority-conflict-holds",
            "evidence": [],
            "candidates": [
                {
                    "schema": CANDIDATE_SCHEMA,
                    "subject": "provider-state",
                    "artifact_id": "provider:a",
                    "kind": "PROVIDER_READBACK",
                    "status": "PASS",
                    "observed_at_utc": "2026-08-22T08:00:00Z",
                    "production_qualified": False,
                    "evidence_debt": False,
                    "current_observation": True,
                    "artifact_sha256": "c" * 64,
                },
                {
                    "schema": CANDIDATE_SCHEMA,
                    "subject": "provider-state",
                    "artifact_id": "provider:b",
                    "kind": "PROVIDER_READBACK",
                    "status": "REJECT",
                    "observed_at_utc": "2026-08-22T08:00:00Z",
                    "production_qualified": False,
                    "evidence_debt": False,
                    "current_observation": True,
                    "artifact_sha256": "d" * 64,
                },
            ],
            "expected": {
                "terminal": "STATE_RESOLUTION_HOLD",
                "reason": "EQUAL_AUTHORITY_CONTRADICTION",
            },
        },
    ]


def run() -> dict[str, Any]:
    frozen = fixtures()
    rows = []
    all_passed = True
    for fixture in frozen:
        result = resolve_state(fixture["candidates"])
        expected = fixture["expected"]
        observed = {
            "terminal": result.get("terminal"),
            "reason": result.get("reason"),
            "selected_kind": (result.get("selected") or {}).get("kind"),
            "selected_status": (result.get("selected") or {}).get("status"),
        }
        ok = all(observed.get(key) == value for key, value in expected.items())
        all_passed &= ok
        rows.append(
            {
                "case_id": fixture["case_id"],
                "expected": expected,
                "observed": observed,
                "ok": ok,
                "evidence": fixture["evidence"],
            }
        )
    return {
        "schema": "continuityos-current-truth-bench-v1",
        "status": "PASS" if all_passed else "FAIL",
        "fixture_count": len(rows),
        "fixture_sha256": canonical_sha256(frozen),
        "cases": rows,
        "authority": {
            "execution_authority": "NONE",
            "can_execute": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "provider_effects": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--manifest-out", required=True)
    args = parser.parse_args(argv)
    report = run()
    write_json(args.json_out, report)
    effective_argv = list(argv) if argv is not None else sys.argv[1:]
    dataset = {
        "kind": "frozen-current-truth-fixtures",
        "sha256": report["fixture_sha256"],
        "fixture_count": report["fixture_count"],
        "network_calls": 0,
        "note": "Frozen regression evidence; fresh live decisions still require provider readback.",
    }
    manifest = build_manifest(
        benchmark_name="current-truth",
        benchmark_source=Path(__file__),
        argv=effective_argv,
        result_path=args.json_out,
        dataset=dataset,
        model={
            "embedder": None,
            "model_name": None,
            "model_revision": None,
            "model_sha256": None,
            "package": None,
            "package_version": None,
            "identity_assurance": "NOT_APPLICABLE_DETERMINISTIC_RULES",
        },
    )
    write_json(args.manifest_out, manifest)
    print(
        json.dumps(
            {
                "status": report["status"],
                "fixture_count": report["fixture_count"],
                "result_sha256": sha256_file(args.json_out),
                "manifest_sha256": sha256_file(args.manifest_out),
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
