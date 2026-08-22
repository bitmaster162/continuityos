from __future__ import annotations
import hashlib
from typing import Any, Iterable, Mapping
from ..gate.evidence_common import canonical_json_text
from .contracts import FederationContractError, _time, _unique, validate_candidate, validate_query
from .policy import *

def _sort(c):
    r=c["result"]; return (c["semantic_key"],ADAPTER_PRIORITY[c["adapter_id"]],r.get("stable_source_ref") or "",c["candidate_id"])

def _eligible(q,c):
    r=c["result"]
    if r["surface"]=="UNKNOWN" or SURFACE_SCOPE[r["surface"]] not in q["scope"]: return False,"OUT_OF_SCOPE"
    if r["status"]=="ABSTAIN": return False,"CANDIDATE_ABSTAIN"
    requested=set(q["source_classes"])
    if requested:
        actual=c.get("source_class")
        if actual is None: return False,"SOURCE_CLASS_UNPROVEN"
        if actual not in requested: return False,"SOURCE_CLASS_FILTERED"
    requested_projects=set(q["project_ids"])
    if requested_projects:
        actual_projects=set(c.get("project_ids",()))
        if not actual_projects: return False,"PROJECT_SCOPE_UNPROVEN"
        if requested_projects.isdisjoint(actual_projects): return False,"PROJECT_SCOPE_FILTERED"
    mode=q["resolution_mode"]
    if r["authority_class"] not in MODE_AUTHORITY[mode]: return False,"AUTHORITY_INCOMPATIBLE"
    if not q["include_superseded"] and mode not in {"HISTORICAL_AS_OF","DISCOVERY","EVIDENCE"} and r["supersession_state"] in {"SUPERSEDED","HISTORICAL"}: return False,"SUPERSEDED_OR_HISTORICAL"
    if mode=="CURRENT_STATE":
        if r["supersession_state"]!="CURRENT": return False,"CURRENT_STATE_REQUIRES_CURRENT_SUPERSESSION"
        if r["freshness"] in {"STALE","UNPROVEN"}: return False,"CURRENT_STATE_FRESHNESS_UNPROVEN"
    if mode=="PHYSICAL_STATE":
        if c["fact_class"]!="PHYSICAL": return False,"PHYSICAL_MODE_REQUIRES_PHYSICAL_FACT"
        if c["binding_strength"] not in PHYSICAL_BINDINGS: return False,"PHYSICAL_MODE_REQUIRES_DIRECT_BINDING"
        if r["freshness"] not in PHYSICAL_FRESHNESS: return False,"PHYSICAL_MODE_REQUIRES_FRESH_DIRECT_READBACK"
    if mode=="OPERATIONAL_RECALL" and c["binding_strength"]!="OPERATIONAL_MEMORY": return False,"OPERATIONAL_MODE_REQUIRES_OPERATIONAL_BINDING"
    cutoff=q.get("observed_before_transaction_time")
    if cutoff is not None and _time(r["transaction_time"]["recorded_at"],"recorded_at")>_time(cutoff,"cutoff"): return False,"TRANSACTION_TIME_AFTER_CUTOFF"
    if mode=="HISTORICAL_AS_OF":
        as_of=_time(q["as_of_valid_time"],"as_of_valid_time"); start=_time(r["valid_time"]["start"],"valid_time.start",True); end=_time(r["valid_time"]["end"],"valid_time.end",True)
        if start is None: return False,"VALID_TIME_START_UNPROVEN"
        if as_of<start or (end is not None and as_of>=end): return False,"OUTSIDE_VALID_TIME"
    return True,None

def resolve_candidates(query: Mapping[str,Any], candidates: Iterable[Mapping[str,Any]], *, sources_unavailable: Iterable[str]=(), coverage_limits: Iterable[str]=()):
    q=validate_query(query); raw=tuple(candidates)
    if len(raw)>MAX_CANDIDATES: raise FederationContractError("too many candidates")
    valid=tuple(validate_candidate(c,q["query_id"]) for c in raw)
    unavailable=_unique(list(sources_unavailable),"sources_unavailable",MAX_COVERAGE_ROWS); limits=_unique(list(coverage_limits),"coverage_limits",MAX_COVERAGE_ROWS)
    discarded=[]; eligible=[]
    for c in valid:
        ok,reason=_eligible(q,c)
        if ok: eligible.append(c)
        else: discarded.append({"candidate_id":c["candidate_id"],"reason":str(reason)})
    aliases={}
    for c in sorted(eligible,key=_sort):
        r=c["result"]; key=(c["semantic_key"],c["payload_digest"],r.get("stable_source_ref"),r["authority_class"],c["source_occurrence_id"])
        if key in aliases: discarded.append({"candidate_id":c["candidate_id"],"reason":"EXACT_RETRIEVAL_ALIAS"})
        else: aliases[key]=c
    eligible=list(aliases.values()); groups={}
    for c in eligible: groups.setdefault(c["semantic_key"],[]).append(c)
    conflicts=[c["candidate_id"] for c in eligible if c["result"]["status"]=="CONFLICT"]
    for group in groups.values():
        if len({c["payload_digest"] for c in group})>1: conflicts.extend(c["candidate_id"] for c in group)
    if conflicts: decision,selected,trace="CONFLICT",[],["FILTER","ALIAS_COLLAPSE","CONFLICT_BEFORE_LIMIT","FAIL_CLOSED"]
    elif not eligible: decision,selected,trace="ABSTAIN",[],["FILTER","NO_ELIGIBLE_CANDIDATE","ABSTAIN"]
    else: decision,selected,trace="HIT",[c["candidate_id"] for c in sorted(eligible,key=_sort)[:q["limit"]]],["FILTER","ALIAS_COLLAPSE","CONFLICT_BEFORE_LIMIT","SORT","LIMIT_LAST"]
    digest_input={"query":q,"candidates":sorted(valid,key=lambda c:c["candidate_id"]),"sources_unavailable":sorted(unavailable),"coverage_limits":sorted(limits)}
    digest=hashlib.sha256(canonical_json_text(digest_input).encode()).hexdigest(); coverage="PARTIAL" if unavailable or limits else ("UNKNOWN" if not valid else "COMPLETE")
    return {"schema":RESOLUTION_SCHEMA,"query_id":q["query_id"],"decision":decision,"coverage_status":coverage,"selected_candidate_ids":selected,"conflict_candidate_ids":sorted(set(conflicts)),"discarded":sorted(discarded,key=lambda x:(x["candidate_id"],x["reason"])),"eligible_before_limit":len(eligible),"sources_unavailable":sorted(unavailable),"coverage_limits":sorted(limits),"rule_trace":trace,"canonical_input_digest":digest,"effect_authority":"NONE","authority":{"resolver_grants_current_truth":False,"resolver_grants_effect_authority":False,"can_trade":False,"capital_permission":"DENY"}}
