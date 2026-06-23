"""preflight() — the non-negotiable invariant: no dangerous tool runs without a decision.
Consumes an ActionSpec + policy, returns a Decision with reasons, rollback plan, and trace,
and records it in the append-only ledger."""
from __future__ import annotations
import os, time
from typing import Dict, Any, Optional, List
from .spec import ActionSpec, DECISIONS
from .classifier import classify, match_protected, SEVERITY_RANK
from .policy import load_policy, DEFAULT_POLICY
from .ledger import Ledger

_ORDER = ["ALLOW", "DRY_RUN_ONLY", "WARN", "REQUIRE_CONFIRMATION", "HOLD", "DENY"]
def _stricter(a: str, b: str) -> str:
    return a if _ORDER.index(a) >= _ORDER.index(b) else b

def _expanduser_paths(paths: List[str]) -> List[str]:
    return [os.path.expanduser(p) for p in (paths or [])]

def preflight(spec: ActionSpec, policy: Optional[Dict[str, Any]] = None,
              ledger: Optional[Ledger] = None, context=None) -> Dict[str, Any]:
    pol = policy or DEFAULT_POLICY
    reasons: List[str] = []
    decision = pol.get("default_decision", "ALLOW")

    # 1) tool allowed?
    if spec.tool not in pol.get("allowed_tools", []):
        decision = _stricter(decision, "HOLD")
        reasons.append(f"tool '{spec.tool}' not in allowed_tools → HOLD for review")

    # 2) dangerous command signals
    sev_dec = pol.get("severity_decision", {})
    sigs = classify(spec.command) if spec.command else []
    top_sev = None
    for s in sigs:
        reasons.append(f"[{s['severity']}] {s['id']}: {s['reason']}")
        d = sev_dec.get(s["severity"], "WARN")
        decision = _stricter(decision, d)
        if top_sev is None or SEVERITY_RANK[s["severity"]] > SEVERITY_RANK[top_sev]:
            top_sev = s["severity"]

    # 3) protected path touch
    protected = match_protected(spec.paths, pol.get("protected_paths", []))
    if protected:
        reasons.append("touches protected paths: " + ", ".join(protected))
        decision = _stricter(decision, pol.get("protected_path_decision", "REQUIRE_CONFIRMATION"))
        if pol.get("dry_run_on_protected_delete") and any(x in spec.command.lower() for x in ("rm", "delete", "del ")):
            decision = _stricter(decision, "DRY_RUN_ONLY")

    # 4) continuity context — does this action conflict with the user's canon (non-negotiable rules)?
    canon_conflict = _canon_check(spec, context)
    if canon_conflict:
        for r in canon_conflict:
            reasons.append("⚖ conflicts with your canon: " + r)
        decision = _stricter(decision, "REQUIRE_CONFIRMATION")

    # 5) SAP — capability passport per agent (State Authority Plane, from AI-guide state-authority-plane)
    sap = _capability_check(spec, pol)
    if sap:
        reasons.extend(sap)
        decision = _stricter(decision, pol.get("capability_decision", "REQUIRE_CONFIRMATION"))

    # 6) D3 — tool-IO schema & limit validation (Tool-IO Bridge, from AI-guide d3-tool-io-bridge)
    schema_issues = _schema_check(spec, pol)
    if schema_issues:
        reasons.extend(schema_issues)
        decision = _stricter(decision, pol.get("schema_decision", "REQUIRE_CONFIRMATION"))

    if not reasons:
        reasons.append("no risk signals; allowed")

    result = {
        "decision": decision,
        "reasons": reasons,
        "severity": top_sev,
        "action": spec.to_dict(),
        "rollback_plan": _rollback_plan(spec, snapshot=(decision in ("DENY","HOLD","REQUIRE_CONFIRMATION","DRY_RUN_ONLY") and bool(spec.paths))),
        "ts": time.time(),
        "invariant": "no registered dangerous tool may execute unless a ContinuityOS preflight decision exists",
    }
    if ledger is not None:
        result["ledger_hash"] = ledger.append("preflight", {
            "agent": spec.agent, "tool": spec.tool, "command": spec.command,
            "decision": decision, "severity": top_sev, "reasons": reasons})
    return result

def _rollback_plan(spec: ActionSpec, snapshot: bool = False) -> Dict[str, Any]:
    """Snapshot affected local files so a destructive change can be undone via
    `continuity rollback <id>`. Honest scope: local files only — cannot undo
    irreversible external side effects (network, prod, external APIs)."""
    info = {"note": "Local file snapshots only. Irreversible external side effects cannot be rolled back."}
    existing = [p for p in _expanduser_paths(spec.paths) if os.path.isfile(p)]
    if snapshot and existing:
        from .rollback import snapshot as _snap
        snap = _snap(existing)
        info.update({"snapshot_id": snap["id"], "files_saved": snap["saved"],
                     "restore_cmd": f"continuity rollback {snap['id']}", "restorable": snap["restorable"]})
    else:
        info["files_affected"] = existing
        info["restorable"] = bool(existing)
    return info


def _canon_check(spec: ActionSpec, context) -> list:
    """If a Memory/Continuity context is supplied, flag actions that conflict with canon rules.
    This is the differentiator: decisions use the user's own non-negotiable rules, not just regex."""
    if context is None:
        return []
    try:
        from ..memory import Memory
        from ..twin import Twin
        mem = context.m if hasattr(context, "m") else context if isinstance(context, Memory) else None
        if mem is None:
            return []
        al = Twin(memory=mem).alignment(spec.command or spec.tool)
        return [c["rule"] for c in al.get("possible_conflicts", [])][:3]
    except Exception:
        return []


def _capability_check(spec, pol):
    """SAP (State Authority Plane): each agent holds a capability passport listing the
    tools it may invoke and a path-count cap. Action exceeding the passport escalates.
    Inert if policy has no 'capabilities' key (backward compatible)."""
    caps = pol.get("capabilities")
    if not caps:
        return []
    passport = caps.get(spec.agent)
    if passport is None:
        return [f"⛨ SAP: agent '{spec.agent}' has no capability passport → escalate"]
    issues = []
    allowed = passport.get("tools", [])
    if allowed and spec.tool not in allowed:
        issues.append(f"⛨ SAP: agent '{spec.agent}' passport lacks tool '{spec.tool}'")
    mp = passport.get("max_paths")
    if mp is not None and len(spec.paths or []) > mp:
        issues.append(f"⛨ SAP: agent '{spec.agent}' exceeds max_paths {mp} ({len(spec.paths or [])} targets)")
    return issues


def _schema_check(spec, pol):
    """D3 (Tool-IO Bridge): validate the action against the tool's I/O schema — forbidden
    patterns, arg-count limits, allowed filesystem roots, allowed http domains.
    Inert if policy has no 'tool_schemas' key (backward compatible)."""
    schemas = pol.get("tool_schemas")
    if not schemas:
        return []
    sch = schemas.get(spec.tool)
    if not sch:
        return []
    issues = []
    cmd = spec.command or ""
    for pat in sch.get("forbid_patterns", []):
        if pat in cmd:
            issues.append(f"⛒ D3: forbidden pattern '{pat}' in {spec.tool}")
    ma = sch.get("max_args")
    if ma is not None and len(spec.args or []) > ma:
        issues.append(f"⛒ D3: {spec.tool} arg-count {len(spec.args or [])} > max {ma}")
    roots = sch.get("allowed_roots")
    if roots:
        for p in _expanduser_paths(spec.paths):
            ap = os.path.abspath(p)
            if not any(ap.startswith(os.path.abspath(os.path.expanduser(r))) for r in roots):
                issues.append(f"⛒ D3: path '{p}' outside allowed roots for {spec.tool}")
    doms = sch.get("allowed_domains")
    if doms and spec.tool in ("http", "https", "fetch"):
        if not any(d in cmd for d in doms):
            issues.append(f"⛒ D3: {spec.tool} target not in allowed domains")
    return issues
