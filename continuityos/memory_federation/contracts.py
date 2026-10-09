from __future__ import annotations
from datetime import datetime
import hashlib
from typing import Any, Mapping

from ..gate.evidence_common import canonical_json_text, require_bool, require_dict, require_list, require_sha, require_str
from .policy import *

QUERY_KEYS = {"schema","query_id","query","resolution_mode","scope","as_of_valid_time","observed_before_transaction_time","source_classes","project_ids","include_conflicts","include_superseded","limit","requested_effect","created_at"}
RESULT_KEYS = {"schema","result_id","query_id","status","surface","stable_source_ref","raw_artifact_ref","provenance_chain","valid_time","transaction_time","freshness","confidence","contradiction_state","supersession_state","authority_class","payload","abstain_reason","effect_authority"}
CANDIDATE_REQUIRED_KEYS = {"candidate_id","adapter_id","semantic_key","fact_class","subject_ref","payload_digest","binding_strength","source_occurrence_id","result"}
CANDIDATE_OPTIONAL_KEYS = {"source_class","project_ids"}

class FederationContractError(ValueError): pass

def _time(value: Any, label: str, optional: bool=False):
    if value is None and optional: return None
    text=require_str(value,label); text=text[:-1]+"+00:00" if text.endswith("Z") else text
    try: parsed=datetime.fromisoformat(text)
    except ValueError as exc: raise FederationContractError(f"{label} must be ISO/RFC3339 date-time") from exc
    if parsed.tzinfo is None: raise FederationContractError(f"{label} must be timezone-aware")
    return parsed

def _unique(value: Any, label: str, maximum: int):
    rows=require_list(value,label,maximum); out=tuple(require_str(x,f"{label}[]") for x in rows)
    if len(out)!=len(set(out)): raise FederationContractError(f"{label} must be unique")
    return out

def _keys(value: Mapping[str,Any], required:set[str], optional:set[str], label:str):
    missing=required.difference(value); extra=set(value).difference(required|optional)
    if missing or extra: raise FederationContractError(f"{label} keys mismatch missing={sorted(missing)} extra={sorted(extra)}")

def validate_query(value: Mapping[str,Any]):
    q=require_dict(value,"query"); _keys(q,QUERY_KEYS,set(),"query")
    if q.get("schema")!=QUERY_SCHEMA: raise FederationContractError(f"query.schema must be {QUERY_SCHEMA}")
    require_str(q.get("query_id"),"query.query_id"); require_str(q.get("query"),"query.query")
    mode=require_str(q.get("resolution_mode"),"query.resolution_mode")
    if mode not in MODES: raise FederationContractError("unsupported resolution_mode")
    scope=_unique(q.get("scope"),"query.scope",len(SCOPES))
    if not scope or any(x not in SCOPES for x in scope): raise FederationContractError("unsupported query.scope")
    if q.get("as_of_valid_time") is not None: _time(q["as_of_valid_time"],"query.as_of_valid_time")
    if mode=="HISTORICAL_AS_OF" and q.get("as_of_valid_time") is None: raise FederationContractError("HISTORICAL_AS_OF requires as_of_valid_time")
    if q.get("observed_before_transaction_time") is not None: _time(q["observed_before_transaction_time"],"query.observed_before_transaction_time")
    _unique(q.get("source_classes"),"query.source_classes",500); _unique(q.get("project_ids"),"query.project_ids",500)
    require_bool(q.get("include_conflicts"),"query.include_conflicts"); require_bool(q.get("include_superseded"),"query.include_superseded")
    limit=q.get("limit")
    if not isinstance(limit,int) or isinstance(limit,bool) or not 1<=limit<=200: raise FederationContractError("query.limit must be integer 1..200")
    if q.get("requested_effect") is not False: raise FederationContractError("query.requested_effect must be false")
    _time(q.get("created_at"),"query.created_at"); return dict(q)

def validate_result(value: Mapping[str,Any], query_id: str|None=None):
    r=require_dict(value,"result"); _keys(r,RESULT_KEYS,set(),"result")
    if r.get("schema")!=RESULT_SCHEMA: raise FederationContractError(f"result.schema must be {RESULT_SCHEMA}")
    require_str(r.get("result_id"),"result.result_id"); rid=require_str(r.get("query_id"),"result.query_id")
    if query_id is not None and rid!=query_id: raise FederationContractError("result.query_id mismatch")
    status=require_str(r.get("status"),"result.status")
    if status not in {"HIT","CONFLICT","ABSTAIN"}: raise FederationContractError("unsupported result.status")
    surface=require_str(r.get("surface"),"result.surface")
    if surface not in SURFACE_SCOPE and surface!="UNKNOWN": raise FederationContractError("unsupported result.surface")
    stable=r.get("stable_source_ref"); raw=r.get("raw_artifact_ref")
    if stable is not None: require_str(stable,"result.stable_source_ref")
    if raw is not None: require_str(raw,"result.raw_artifact_ref")
    provenance=_unique(r.get("provenance_chain"),"result.provenance_chain",1000)
    valid=require_dict(r.get("valid_time"),"result.valid_time"); _keys(valid,{"start","end"},set(),"result.valid_time")
    start=_time(valid.get("start"),"result.valid_time.start",True); end=_time(valid.get("end"),"result.valid_time.end",True)
    if start is not None and end is not None and end<=start: raise FederationContractError("valid_time.end must be after start")
    tx=require_dict(r.get("transaction_time"),"result.transaction_time"); _keys(tx,{"observed_at","recorded_at"},set(),"result.transaction_time")
    _time(tx.get("observed_at"),"result.transaction_time.observed_at"); _time(tx.get("recorded_at"),"result.transaction_time.recorded_at")
    if r.get("freshness") not in {"FRESH_PROVIDER","FRESH_LOCAL_RUNTIME","SEALED_HISTORICAL","STALE","UNPROVEN"}: raise FederationContractError("unsupported freshness")
    confidence=r.get("confidence")
    if not isinstance(confidence,(int,float)) or isinstance(confidence,bool) or not 0<=confidence<=1: raise FederationContractError("confidence must be 0..1")
    if r.get("contradiction_state") not in {"NONE_KNOWN","CONFLICT_PRESENT","SEARCH_INCOMPLETE","UNPROVEN"}: raise FederationContractError("unsupported contradiction_state")
    if r.get("supersession_state") not in {"CURRENT","SUPERSEDED","HISTORICAL","CANDIDATE","UNPROVEN"}: raise FederationContractError("unsupported supersession_state")
    authority=r.get("authority_class")
    if authority not in {"RAW_EVIDENCE","EVIDENCE_ONLY","CURRENT_TRUTH","OPERATIONAL_MEMORY","NONE"}: raise FederationContractError("unsupported authority_class")
    if r.get("effect_authority")!="NONE": raise FederationContractError("effect_authority must be NONE")
    reason=r.get("abstain_reason")
    if status=="ABSTAIN":
        require_str(reason,"result.abstain_reason")
        if authority!="NONE": raise FederationContractError("ABSTAIN authority_class must be NONE")
    else:
        if stable is None or not provenance: raise FederationContractError("HIT/CONFLICT requires stable source and provenance")
        if reason is not None: raise FederationContractError("HIT/CONFLICT abstain_reason must be null")
    if status=="CONFLICT" and r.get("contradiction_state")!="CONFLICT_PRESENT": raise FederationContractError("CONFLICT requires contradiction_state=CONFLICT_PRESENT")
    return dict(r)

def _payload_digest(payload: Any):
    text=canonical_json_text(payload); text=text[:-1] if text.endswith("\n") else text
    return hashlib.sha256(text.encode()).hexdigest()

def validate_candidate(value: Mapping[str,Any], query_id: str|None=None):
    c=require_dict(value,"candidate"); _keys(c,CANDIDATE_REQUIRED_KEYS,CANDIDATE_OPTIONAL_KEYS,"candidate")
    require_str(c.get("candidate_id"),"candidate.candidate_id"); adapter=require_str(c.get("adapter_id"),"candidate.adapter_id")
    if adapter not in ADAPTER_ALLOWED_AUTHORITY: raise FederationContractError(f"unregistered adapter_id: {adapter}")
    require_str(c.get("semantic_key"),"candidate.semantic_key")
    if c.get("fact_class") not in {"PHYSICAL","SEMANTIC","PREFERENCE","HISTORICAL","DISCOVERY"}: raise FederationContractError("unsupported fact_class")
    require_str(c.get("subject_ref"),"candidate.subject_ref")
    if "source_class" in c: require_str(c.get("source_class"),"candidate.source_class")
    if "project_ids" in c: _unique(c.get("project_ids"),"candidate.project_ids",500)
    digest=require_sha(c.get("payload_digest"),"candidate.payload_digest"); binding=c.get("binding_strength")
    if binding not in ADAPTER_ALLOWED_BINDINGS[adapter]: raise FederationContractError(f"{adapter} may not emit binding_strength={binding}")
    require_str(c.get("source_occurrence_id"),"candidate.source_occurrence_id"); r=validate_result(c.get("result"),query_id)
    if r["authority_class"] not in ADAPTER_ALLOWED_AUTHORITY[adapter]: raise FederationContractError(f"{adapter} may not emit authority_class={r['authority_class']}")
    if r["surface"] not in ADAPTER_ALLOWED_SURFACES[adapter]: raise FederationContractError(f"{adapter} may not emit surface={r['surface']}")
    if r["freshness"] not in ADAPTER_ALLOWED_FRESHNESS[adapter]: raise FederationContractError(f"{adapter} may not emit freshness={r['freshness']}")
    if r["status"]!="ABSTAIN" and digest!=_payload_digest(r["payload"]): raise FederationContractError("candidate.payload_digest does not match result.payload")
    return dict(c)
