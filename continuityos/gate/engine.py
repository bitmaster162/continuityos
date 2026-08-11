"""Decision engine for execution paths that explicitly call ``preflight``.

It consumes an ActionSpec and policy, then returns reasons, rollback intent, and a
trace. Enforcement remains the responsibility of a wired executor or host hook.
"""
from __future__ import annotations
import os, re, shlex, subprocess, time
from typing import Dict, Any, Optional, List
from urllib.parse import urlsplit
from .spec import ActionSpec
from .classifier import (classify, extract_candidate_paths, match_protected,
                         path_within, SEVERITY_RANK)
from .policy import DEFAULT_POLICY, policy_fingerprint
from .ledger import Ledger

_ORDER = ["ALLOW", "DRY_RUN_ONLY", "WARN", "REQUIRE_CONFIRMATION", "HOLD", "DENY"]
_ERASURE_SIGNAL_IDS = {
    "rm_rf", "rm_root", "ps_recursive_delete", "cmd_recursive_delete",
    "generic_delete", "git_clean", "interp_delete", "find_delete",
    "find_exec_rm", "truncate_cmd", "shred", "redirect_wipe",
    "wipe_cmds", "history_clear",
}


def _stricter(a: str, b: str) -> str:
    return a if _ORDER.index(a) >= _ORDER.index(b) else b

def _expanduser_paths(paths: List[str]) -> List[str]:
    return [os.path.expanduser(p) for p in (paths or [])]

def preflight(spec: ActionSpec, policy: Optional[Dict[str, Any]] = None,
              ledger: Optional[Ledger] = None, context=None) -> Dict[str, Any]:
    pol = policy if policy is not None else DEFAULT_POLICY
    reasons: List[str] = []
    decision = pol.get("default_decision", "ALLOW")
    paths_valid = isinstance(spec.paths, (list, tuple)) and all(
        isinstance(p, str) and bool(p) for p in spec.paths
    )
    args_valid = isinstance(spec.args, (list, tuple)) and all(isinstance(a, str) for a in spec.args)
    declared_paths = list(spec.paths) if paths_valid else []
    if not paths_valid:
        reasons.append("ActionSpec.paths must be a list of non-empty strings")
        decision = _stricter(decision, "HOLD")
    if not args_valid:
        reasons.append("ActionSpec.args must be a list of strings")
        decision = _stricter(decision, "HOLD")
    argv_command = _render_args(spec.args) if args_valid and spec.args else ""
    if spec.tool == "exec":
        if not argv_command:
            reasons.append("exec action requires the exact non-empty argument vector")
            decision = _stricter(decision, "HOLD")
        elif spec.command != argv_command:
            reasons.append(
                "exec command does not exactly match the canonical argument vector"
            )
            decision = _stricter(decision, "HOLD")
    assessment_commands = list(dict.fromkeys(
        command for command in (spec.command, argv_command) if command
    ))
    inferred_paths = []
    for command in assessment_commands:
        inferred_paths.extend(extract_candidate_paths(command))
    inferred_paths = list(dict.fromkeys(inferred_paths))
    effective_paths = list(dict.fromkeys(declared_paths + inferred_paths))

    # Adapter/runtime failures are explicit typed evidence, never silent fallback.
    policy_error = (spec.meta or {}).get("policy_error")
    context_error = (spec.meta or {}).get("context_error")
    if policy_error:
        reasons.append(f"policy load failed: {policy_error}")
        decision = _stricter(decision, "HOLD")
    if context_error:
        reasons.append(f"continuity context unavailable: {context_error}")
        decision = _stricter(decision, pol.get("context_error_decision", "HOLD"))
    trusted_context_identity = None
    context_identity_error = None

    # 1) tool allowed?
    if spec.tool not in pol.get("allowed_tools", []):
        decision = _stricter(decision, "HOLD")
        reasons.append(f"tool '{spec.tool}' not in allowed_tools → HOLD for review")

    # 2) dangerous command signals
    sev_dec = pol.get("severity_decision", {})
    sigs = []
    seen_signal_ids = set()
    for command in assessment_commands:
        for signal in classify(command):
            if signal["id"] not in seen_signal_ids:
                sigs.append(signal)
                seen_signal_ids.add(signal["id"])
    erasure_signals = {signal["id"] for signal in sigs} & _ERASURE_SIGNAL_IDS
    top_sev = None
    for s in sigs:
        reasons.append(f"[{s['severity']}] {s['id']}: {s['reason']}")
        d = sev_dec.get(s["severity"], "WARN")
        decision = _stricter(decision, d)
        if top_sev is None or SEVERITY_RANK[s["severity"]] > SEVERITY_RANK[top_sev]:
            top_sev = s["severity"]

    mutating = _is_mutating(spec) or bool(erasure_signals)
    if spec.tool == "file.delete":
        reasons.append("file.delete is a destructive typed action")
        decision = _stricter(decision, sev_dec.get("high", "REQUIRE_CONFIRMATION"))
        top_sev = top_sev or "high"
    if mutating and not effective_paths:
        reasons.append("mutating action has no typed or inferable target paths")
        decision = _stricter(decision, pol.get("missing_paths_decision", "REQUIRE_CONFIRMATION"))
    relative_targets = [
        p for p in effective_paths
        if not os.path.isabs(os.path.expandvars(os.path.expanduser(p)))
    ]
    if mutating and relative_targets and not _authoritative_cwd(spec.cwd):
        reasons.append("mutating action has relative targets but no authoritative cwd")
        decision = _stricter(decision, pol.get("missing_cwd_decision", "HOLD"))

    # 3) protected path touch
    protected = match_protected(effective_paths, pol.get("protected_paths", []), spec.cwd)
    protected_delete_dry_run = False
    if protected:
        reasons.append("touches protected paths: " + ", ".join(protected))
        decision = _stricter(decision, pol.get("protected_path_decision", "REQUIRE_CONFIRMATION"))
        if pol.get("dry_run_on_protected_delete") and (
            erasure_signals or _is_delete(spec)
        ):
            protected_delete_dry_run = True
            reasons.append(
                "protected delete is DRY_RUN_ONLY; ordinary confirmation cannot authorize execution"
            )

    # 4) continuity context — does this action conflict with the user's canon (non-negotiable rules)?
    canon_conflict = []
    canon_error = None
    if context is not None:
        try:
            from ..db import context_identity, context_read_snapshot
            with context_read_snapshot(context):
                trusted_context_identity = context_identity(context)
                canon_conflict, canon_error = _canon_check(spec, context)
        except Exception as exc:
            context_identity_error = f"{type(exc).__name__}: {exc}"
            reasons.append(
                "continuity context identity/evaluation unavailable: "
                + context_identity_error
            )
            decision = _stricter(
                decision, pol.get("context_error_decision", "HOLD")
            )
    if canon_conflict:
        for r in canon_conflict:
            reasons.append("conflicts with your canon: " + r)
        decision = _stricter(decision, "REQUIRE_CONFIRMATION")
    if canon_error:
        reasons.append("continuity context evaluation failed: " + canon_error)
        decision = _stricter(decision, pol.get("context_error_decision", "HOLD"))

    # 5) SAP — capability passport per agent (State Authority Plane, from AI-guide state-authority-plane)
    sap = _capability_check(spec, pol, effective_paths)
    if sap:
        reasons.extend(sap)
        decision = _stricter(decision, pol.get("capability_decision", "REQUIRE_CONFIRMATION"))

    # 6) D3 — tool-IO schema & limit validation (Tool-IO Bridge, from AI-guide d3-tool-io-bridge)
    schema_issues = _schema_check(spec, pol, effective_paths)
    if schema_issues:
        reasons.extend(schema_issues)
        decision = _stricter(decision, pol.get("schema_decision", "REQUIRE_CONFIRMATION"))

    # DRY_RUN_ONLY is a mode, not a weaker risk severity.  Re-apply it after
    # confirmation-class checks so a normal yes/no prompt cannot become a
    # break-glass contract.  DENY/HOLD remain strictly non-executable.
    if protected_delete_dry_run and decision not in ("DENY", "HOLD"):
        decision = "DRY_RUN_ONLY"

    if not reasons:
        reasons.append("no risk signals; allowed")

    may_execute = decision in ("ALLOW", "WARN", "REQUIRE_CONFIRMATION")
    snapshot = may_execute and bool(declared_paths) and mutating
    rollback_plan = _rollback_plan(spec, declared_paths, snapshot=snapshot)
    context_errors = [
        error for error in (context_error, context_identity_error, canon_error)
        if error
    ]
    context_trace = {
        "supplied": context is not None,
        "conflicts": canon_conflict,
        "error": "; ".join(context_errors) if context_errors else None,
        "identity": trusted_context_identity,
    }
    policy_trace = {
        "version": pol.get("version"),
        "sha256": policy_fingerprint(pol),
    }
    result = {
        "decision": decision,
        "reasons": reasons,
        "severity": top_sev,
        "action": spec.to_dict(),
        "assessed_paths": effective_paths,
        "rollback_plan": rollback_plan,
        "policy": policy_trace,
        "context": context_trace,
        "ts": time.time(),
        "invariant": "this decision governs only execution paths explicitly wired through this preflight",
    }
    if ledger is not None:
        result["ledger_hash"] = ledger.append("preflight", {
            "action": spec.to_dict(),
            "assessed_paths": effective_paths,
            "decision": decision,
            "severity": top_sev,
            "reasons": reasons,
            "policy": policy_trace,
            "context": context_trace,
            "rollback_plan": rollback_plan,
            "decision_ts": result["ts"],
        })
    return result


def _is_mutating(spec: ActionSpec) -> bool:
    if spec.tool in ("file.write", "file.delete"):
        return True
    cmd = (spec.command or "").strip()
    return bool(re.search(
        r"(^|\s)(rm|del|erase|rmdir|remove-item|move-item|mv|cp|copy|write|truncate|shred|touch|mkdir|"
        r"new-item|set-content|add-content)(\s|$)|(^|[^>])>>?|\btee\b",
        cmd,
        re.IGNORECASE,
    ))


def _render_args(args) -> str:
    values = list(args)
    return (
        subprocess.list2cmdline(values)
        if os.name == "nt"
        else shlex.join(values)
    )


def _authoritative_cwd(cwd: str) -> bool:
    if not isinstance(cwd, str) or not cwd.strip():
        return False
    expanded = os.path.expandvars(os.path.expanduser(cwd))
    return os.path.isabs(expanded)


def _is_delete(spec: ActionSpec) -> bool:
    if spec.tool == "file.delete":
        return True
    return bool(re.search(
        r"(^|[\s;&|/\"'\\(){}\x60])(rm|del|erase|rmdir|rd|ri|remove-item|unlink|shred|srm|wipe|sdelete(?:64)?)"
        r"(\s|$)|\bfind\b.*\s-delete\b|\btruncate\b[^\n]*-s\s*0\b",
        spec.command or "",
        re.IGNORECASE,
    ))


def _can_create_supported_file(spec: ActionSpec, lexical_paths: List[str]) -> bool:
    if spec.tool == "file.write":
        return True
    command = spec.command or ""
    if re.search(r"(^|\s)cp(\s|$)", command, re.IGNORECASE):
        if re.search(
            r"(^|\s)(--recursive|--archive|-[A-Za-z]*[aArR][A-Za-z]*)(\s|$)",
            command,
        ):
            return False
        if len(lexical_paths) >= 2 and os.path.isdir(lexical_paths[-2]):
            return False
        return True
    if re.search(r"(^|\s)copy(\s|$)", command, re.IGNORECASE):
        return True
    return bool(re.search(
        r"(^|\s)(touch|set-content|add-content)(\s|$)|(^|[^>])>>?|\btee\b",
        command,
        re.IGNORECASE,
    ))


def _rollback_plan(spec: ActionSpec, paths: List[str], snapshot: bool = False) -> Dict[str, Any]:
    """Describe rollback intent without copying data during an advisory preflight.

    The controlled CLI materializes this plan immediately before approved execution.
    Other adapters must do the same or honestly report ``restorable=false``.
    """
    info = {
        "note": "Local targets only; external side effects and TOCTOU changes are not reversible.",
        "restorable": False,
        "snapshot_required": bool(snapshot),
    }
    base = os.path.abspath(os.path.expanduser(spec.cwd or os.getcwd()))
    targets = []
    for path in paths:
        lexical = os.path.expandvars(os.path.expanduser(path))
        if not os.path.isabs(lexical):
            lexical = os.path.join(base, lexical)
        targets.append(os.path.abspath(os.path.normpath(lexical)))
    lexical_paths = list(targets)
    if targets and re.search(r"(^|\s)(cp|copy)(\s|$)", spec.command or "", re.IGNORECASE):
        targets = targets[-1:]
    info["targets"] = targets
    info["allow_missing_files"] = _can_create_supported_file(spec, lexical_paths)
    if snapshot:
        info["note"] += " Snapshot must be materialized by the executor before execution."
    return info


def _canon_check(spec: ActionSpec, context):
    """If a Memory/Continuity context is supplied, flag actions that conflict with canon rules.
    This is the differentiator: decisions use the user's own non-negotiable rules, not just regex."""
    if context is None:
        return [], None
    try:
        from ..memory import Memory
        from ..twin import Twin
        mem = context.m if hasattr(context, "m") else context if isinstance(context, Memory) else None
        if mem is None:
            return [], f"unsupported context type: {type(context).__name__}"
        al = Twin(memory=mem).alignment(spec.command or spec.tool)
        return [c["rule"] for c in al.get("possible_conflicts", [])][:3], None
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"


def _capability_check(spec, pol, paths):
    """SAP (State Authority Plane): each agent holds a capability passport listing the
    tools it may invoke and a path-count cap. Action exceeding the passport escalates.
    Inert if policy has no 'capabilities' key (backward compatible)."""
    caps = pol.get("capabilities")
    if not caps:
        return []
    passport = caps.get(spec.agent)
    if passport is None:
        return [f"SAP: agent '{spec.agent}' has no capability passport; escalate"]
    issues = []
    allowed = passport.get("tools", [])
    if allowed and spec.tool not in allowed:
        issues.append(f"SAP: agent '{spec.agent}' passport lacks tool '{spec.tool}'")
    mp = passport.get("max_paths")
    if mp is not None and len(paths) > mp:
        issues.append(f"SAP: agent '{spec.agent}' exceeds max_paths {mp} ({len(paths)} targets)")
    return issues


def _schema_check(spec, pol, paths):
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
            issues.append(f"D3: forbidden pattern '{pat}' in {spec.tool}")
    ma = sch.get("max_args")
    if ma is not None and len(spec.args or []) > ma:
        issues.append(f"D3: {spec.tool} arg-count {len(spec.args or [])} > max {ma}")
    roots = sch.get("allowed_roots")
    if roots:
        for p in _expanduser_paths(paths):
            if not any(path_within(p, r, spec.cwd) for r in roots):
                issues.append(f"D3: path '{p}' outside allowed roots for {spec.tool}")
    doms = sch.get("allowed_domains")
    if doms and spec.tool in ("http", "https", "fetch"):
        urls = re.findall(r"https?://[^\s'\"<>]+", cmd, re.IGNORECASE)
        hosts = [urlsplit(url).hostname for url in urls]
        allowed = [str(domain).lower().strip().strip(".") for domain in doms]
        if not hosts or any(
            not host or not any(
                host.lower().rstrip(".") == domain
                or host.lower().rstrip(".").endswith("." + domain)
                for domain in allowed
            )
            for host in hosts
        ):
            issues.append(f"D3: {spec.tool} target not in allowed domains")
    return issues
