"""Local, synthetic-only client showcase over the existing P2A/P2C/P2D stack.

This is a presentation adapter: no new memory engine, policy evaluator,
external connector, model invocation, or execution authority.
Launch from a verified source checkout:
    python -B -m demo.company_twin_client_demo --check
    python -B -m demo.company_twin_client_demo
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from http import HTTPStatus
import json
from pathlib import Path
from typing import Any

from continuityos.company_twin import load_dataset
from continuityos.company_twin_console import (
    _ConsoleHandler, build_snapshot, make_server, validate_bundle,
)
from continuityos.company_twin_policy import ACTIONS

ROOT = Path(__file__).resolve().parent.parent
BASE_FIXTURE = ROOT / "examples" / "company_twin" / "northstar_labs_2025.json"
HTML_FILE = Path(__file__).with_suffix(".html")
DEMO_PORT = 8769
DEMO_PERIOD = ("2025-01-01T00:00:00Z", "2025-12-31T23:59:59Z")
TENANT = "tenant:northstar-synthetic-demo"

# Exactly twelve fictional humans (including one director), plus one managed agent.
# Every human belongs to a single organizational slot, not to a real directory.
PEOPLE = (
    ("alice", "Alice Chen", "DIRECTOR", None, "Director"),
    ("bob", "Bob Reyes", "WORKER", "sales", "Sales Lead"),
    ("maya", "Maya Ford", "WORKER", "sales", "Account Executive"),
    ("pavel", "Pavel Neri", "WORKER", "sales", "Growth Analyst"),
    ("sue", "Sue Calder", "WORKER", "sales", "Customer Success"),
    ("dana", "Dana Moore", "WORKER", "product", "Product Operations / Finance"),
    ("lena", "Lena Vale", "WORKER", "product", "Product Designer"),
    ("iris", "Iris Reed", "WORKER", "product", "Product Research"),
    ("owen", "Owen Park", "WORKER", "product", "Product Manager"),
    ("cara", "Cara Ionescu", "WORKER", "engineering", "Engineering Lead"),
    ("eli", "Eli Hart", "WORKER", "engineering", "Backend Engineer"),
    ("felix", "Felix Rowan", "WORKER", "engineering", "Quality Engineer"),
)
AUTHOR_BY_DECISION = {
    "dec_jan_smb": "alice",
    "dec_mar_pause_paid": "bob",
    "dec_jun_hiring_freeze": "dana",
    "dec_sep_resume_paid": "bob",
    "dec_nov_deprecate_v1": "owen",
}
FAKE_SOURCES = (
    # id, kind, title, timestamp, scope, source_authority_id, source_ref
    ("ev_demo_sales_mail", "email", "Sales email: partners request a smaller pilot",
     "2025-03-16T09:00:00Z", "team:sales", "auth_drive", "synthetic://mail/sales-mar"),
    ("ev_demo_eng_task", "task", "Task ENG-104: review onboarding regression",
     "2025-04-22T10:00:00Z", "team:engineering", "auth_github", "synthetic://tasks/ENG-104"),
    ("ev_demo_sales_task", "task", "Task SALES-17: qualify partner opportunities",
     "2025-09-16T08:00:00Z", "team:sales", "auth_crm", "synthetic://tasks/SALES-17"),
    ("ev_demo_product_mail", "email", "Product email: friction in trial activation",
     "2025-10-12T10:00:00Z", "team:product", "auth_drive", "synthetic://mail/product-oct"),
)
FAKE_EVENTS = (
    ("evt_demo_sales_mail", "Sales reviewed fictional partner requests",
     "2025-03-17T10:00:00Z", "team:sales", "ent_sales", "ev_demo_sales_mail"),
    ("evt_demo_eng_task", "Engineering assigned onboarding regression review",
     "2025-04-23T13:00:00Z", "team:engineering", "ent_eng", "ev_demo_eng_task"),
    ("evt_demo_sales_task", "Sales started partner qualification task",
     "2025-09-16T12:00:00Z", "team:sales", "ent_sales", "ev_demo_sales_task"),
    ("evt_demo_product_mail", "Product collected synthetic trial feedback",
     "2025-10-13T12:00:00Z", "team:product", "ent_product_team", "ev_demo_product_mail"),
)


def build_demo_bundle() -> dict[str, Any]:
    """Decorate the already-qualified 2025 P2A fixture; P2C/P2D do actual governance."""
    memory = deepcopy(load_dataset(BASE_FIXTURE))
    if memory["organization"].get("synthetic") is not True:
        raise ValueError("DEMO_REQUIRES_SYNTHETIC_ORGANIZATION")
    if (memory["period"]["start"], memory["period"]["end"]) != DEMO_PERIOD:
        raise ValueError("DEMO_SOURCE_PERIOD_DRIFT")

    names = {pid: name for pid, name, *_ in PEOPLE}
    original = {item["id"]: item for item in memory["principals"]}
    if set(original) != {"alice", "bob", "cara", "dana"}:
        raise ValueError("DEMO_SOURCE_PRINCIPALS_DRIFT")
    principals = []
    actors = []
    grants = []
    all_scopes = ["company", "team:sales", "team:product", "team:engineering",
                  "restricted:finance"]
    for pid, name, role, team, title in PEOPLE:
        scopes = list(all_scopes) if role == "DIRECTOR" else ["company", "team:" + team]
        if pid == "dana":
            scopes.append("restricted:finance")
        principals.append({"id": pid, "name": name, "role": role, "scopes": scopes})
        actor = {"id": "actor:" + pid, "principal_id": pid, "actor_kind": "HUMAN",
                 "role": role, "name": name, "job_title": title, "scopes": list(scopes)}
        if team:
            actor.update(team_id=team, manager_actor_id="actor:alice")
        actors.append(actor)
        grants.append({"id": "grant:" + pid, "actor_id": actor["id"],
                       "actions": sorted(ACTIONS) if role == "DIRECTOR" else ["READ", "PROPOSE"],
                       "scopes": list(scopes)})

    robot_id = "agent_atlas"
    principals.append({"id": robot_id, "name": "Atlas Research Agent",
                       "role": "AGENT", "scopes": ["company", "team:engineering"]})
    actors.append({"id": "actor:" + robot_id, "principal_id": robot_id,
                   "name": "Atlas Research Agent", "actor_kind": "AGENT", "role": "AGENT",
                   "team_id": "engineering", "scopes": ["company", "team:engineering"],
                   "manager_actor_id": "actor:cara"})
    memory["principals"] = principals

    for decision in memory["decisions"]:
        pid = AUTHOR_BY_DECISION.get(decision["id"])
        if pid is None:
            raise ValueError("DEMO_UNATTRIBUTED_DECISION")
        decision["decided_by_principal"] = pid
        decision["decided_by_name"] = names[pid]
        # The historical rationale and evidence references stay unchanged.

    for rid, kind, title, when, scope, authority, ref in FAKE_SOURCES:
        memory["evidence"].append({"id": rid, "kind": kind, "title": title,
            "recorded_at": when, "scope": scope, "truth_class": "EVIDENCE",
            "source_authority_id": authority, "source_ref": ref})
    for rid, title, when, scope, entity, evidence in FAKE_EVENTS:
        memory["events"].append({"id": rid, "title": title, "occurred_at": when,
            "scope": scope, "truth_class": "FACT", "entity_ids": [entity],
            "evidence_ids": [evidence]})

    policy = {"schema_version": "company-twin-p2c/1", "tenant_id": TENANT,
              "actors": actors, "grants": grants,
              "delegations": [{
                  "id": "delegation:atlas-research",
                  "grantor_actor_id": "actor:alice",
                  "grantee_actor_id": "actor:" + robot_id,
                  "actions": ["READ", "PROPOSE"], "scopes": ["team:engineering"],
                  "parent_id": None, "expires_at": "2026-01-01T00:00:00Z",
                  "revoked": False,
              }], "explicit_denies": [], "revoked_delegation_ids": []}
    bundle = {"schema_version": "company-twin-console-bundle/1",
              "memory": memory, "policy": policy,
              "proposals": [{
                  "id": "proposal:atlas-regression",
                  "actor_principal_id": robot_id, "scope": "team:engineering",
                  "classification": "INTERNAL", "created_at": "2025-09-20T10:00:00Z",
                  "status": "PENDING_HUMAN_REVIEW",
                  "summary": "Suggest a regression checklist for onboarding. No action executed.",
              }],
              "runtime": {"mode": "SYNTHETIC_LOCAL_DEMO", "read_only": True,
                          "twin_baseline": "P2A-P2D", "execution_authority": "NONE",
                          "can_execute": False}}
    validate_bundle(bundle)
    if (sum(actor["actor_kind"] == "HUMAN" for actor in actors) != 12
            or {actor["team_id"] for actor in actors if "team_id" in actor} !=
               {"sales", "product", "engineering"}):
        raise ValueError("DEMO_ORGANIZATION_SHAPE_INVALID")
    return bundle


class ClientDemoHandler(_ConsoleHandler):
    """Reuse the existing GET /api/snapshot and HTTP write-deny policy unchanged."""

    def _send_html(self, *, head_only: bool = False) -> None:
        body = HTML_FILE.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; connect-src 'self'; "
                         "script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "base-uri 'none'; form-action 'none'")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)


def make_demo_server(*, host: str = "127.0.0.1", port: int = DEMO_PORT):
    server = make_server(host=host, port=port, bundle=build_demo_bundle())
    server.RequestHandlerClass = ClientDemoHandler
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fictional Northstar Labs Company Twin showcase")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEMO_PORT)
    parser.add_argument("--check", action="store_true", help="Offline smoke; do not start HTTP")
    args = parser.parse_args(argv)
    if args.check:
        bundle = build_demo_bundle()
        early = build_snapshot(bundle, principal_id="alice", as_of="2025-03-31T23:59:59Z")
        late = build_snapshot(bundle, principal_id="alice", as_of="2025-12-31T23:59:59Z")
        robot = build_snapshot(bundle, principal_id="agent_atlas", as_of="2025-12-31T23:59:59Z")
        print(json.dumps({"status": "PASS", "synthetic": True,
                          "human_count": 12, "teams": 3,
                          "early_decisions": early["counts"]["decisions"],
                          "late_decisions": late["counts"]["decisions"],
                          "agent_can_execute": robot["capabilities"]["EXECUTE"]["allowed"]},
                         sort_keys=True))
        return 0
    server = make_demo_server(host=args.host, port=args.port)
    print(f"SYNTHETIC DEMO ONLY · http://{args.host}:{server.server_address[1]}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
