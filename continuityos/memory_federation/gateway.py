from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Protocol, Sequence, runtime_checkable
from ..gate.evidence_common import require_str
from .contracts import FederationContractError, validate_query
from .policy import ADAPTER_ALLOWED_AUTHORITY, RESPONSE_SCHEMA
from .resolver import _sort, resolve_candidates

@runtime_checkable
class ReadOnlyFederationAdapter(Protocol):
    adapter_id: str
    def query(self, query: Mapping[str,Any]) -> Sequence[Mapping[str,Any]]: ...

@dataclass(frozen=True)
class StaticAdapter:
    adapter_id: str
    candidates: tuple[Mapping[str,Any],...]
    def __post_init__(self):
        if self.adapter_id not in ADAPTER_ALLOWED_AUTHORITY: raise FederationContractError(f"unregistered adapter_id: {self.adapter_id}")
    def query(self, query):
        q=validate_query(query); return tuple(c for c in self.candidates if c.get("result",{}).get("query_id")==q["query_id"])

@dataclass(frozen=True)
class FederationReadResult:
    resolution: Mapping[str,Any]
    response: Mapping[str,Any]
    candidates: tuple[Mapping[str,Any],...]

class MemoryFederation:
    """Read-only adapter fan-in; intentionally has no write/effect method."""
    def __init__(self, adapters: Sequence[ReadOnlyFederationAdapter]):
        ids=[require_str(a.adapter_id,"adapter.adapter_id") for a in adapters]
        if len(ids)!=len(set(ids)): raise FederationContractError("adapter_id values must be unique")
        if any(x not in ADAPTER_ALLOWED_AUTHORITY for x in ids): raise FederationContractError("all adapters must be registered in capability policy")
        self._adapters=tuple(adapters)
    @property
    def adapter_ids(self): return tuple(a.adapter_id for a in self._adapters)
    def read(self, query, *, unavailable_adapters: Iterable[str]=(), coverage_limits: Iterable[str]=()):
        q=validate_query(query); unavailable=set(unavailable_adapters); limits=tuple(coverage_limits); unknown=unavailable.difference(self.adapter_ids)
        if unknown: raise FederationContractError("unknown unavailable adapters: "+",".join(sorted(unknown)))
        candidates=[]; consulted=[]
        for adapter in self._adapters:
            if adapter.adapter_id in unavailable: continue
            consulted.append(adapter.adapter_id); rows=adapter.query(q)
            for row in rows:
                if row.get("adapter_id")!=adapter.adapter_id: raise FederationContractError("adapter emitted candidate under different adapter_id")
            candidates.extend(rows)
        resolution=resolve_candidates(q,candidates,sources_unavailable=sorted(unavailable),coverage_limits=limits)
        if resolution["decision"]=="ABSTAIN": gateway_status="ABSTAIN"; results=[]
        else:
            gateway_status="PARTIAL" if resolution["coverage_status"]=="PARTIAL" else ("PASS_WITH_CONDITIONS" if resolution["decision"]=="CONFLICT" else "PASS")
            selected=set(resolution["selected_candidate_ids"]); conflicts=set(resolution["conflict_candidate_ids"]); results=[]
            for candidate in sorted(candidates,key=_sort):
                cid=candidate["candidate_id"]
                if cid not in selected and cid not in conflicts: continue
                if cid in conflicts and not q["include_conflicts"]: continue
                result=dict(candidate["result"])
                if cid in conflicts: result["status"]="CONFLICT"; result["contradiction_state"]="CONFLICT_PRESENT"
                results.append(result)
        response={"schema":RESPONSE_SCHEMA,"query_id":q["query_id"],"executed_at":datetime.now(timezone.utc).isoformat(),"results":results,"gateway_status":gateway_status,"sources_consulted":sorted(consulted),"sources_unavailable":sorted(unavailable),"coverage_limits":sorted(set(limits)),"authority":{"read_only":True,"grants_current_truth":False,"grants_effect_authority":False,"can_trade":False,"capital_permission":"DENY"}}
        return FederationReadResult(resolution,response,tuple(candidates))
