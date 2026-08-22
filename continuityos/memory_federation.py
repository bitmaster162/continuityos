"""Read-only, fail-closed memory federation for ContinuityOS.

Adapters only produce evidence candidates. The deterministic resolver returns
HIT / CONFLICT / ABSTAIN and never grants CURRENT_TRUTH or effect authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Iterable, Mapping, Protocol, Sequence, runtime_checkable

from .gate.evidence_common import (
    canonical_json_text,
    require_bool,
    require_dict,
    require_list,
    require_sha,
    require_str,
)

QUERY_SCHEMA = "continuityos.memory_federation_query/v2"
RESULT_SCHEMA = "continuityos.memory_federation_result/v1"
RESOLUTION_SCHEMA = "continuityos.memory_federation_resolution/v1"
RESPONSE_SCHEMA = "continuityos.memory_federation_response/v1"

MODES = frozenset({
    "DISCOVERY", "EVIDENCE", "CURRENT_STATE", "HISTORICAL_AS_OF",
    "OPERATIONAL_RECALL", "PHYSICAL_STATE",
})
SCOPES = frozenset({
    "RAW_CUSTODY", "FROZEN_EVIDENCE", "GOVERNED_KNOWLEDGE",
    "CURRENT_PROJECTION", "TWIN_OPERATIONAL",
})
SURFACE_SCOPE = {
    "RAW_CUSTODY": "RAW_CUSTODY",
    "R1_4R": "FROZEN_EVIDENCE",
    "R1_4R_ROUTER": "FROZEN_EVIDENCE",
    "POSTGRES_GOVERNED": "GOVERNED_KNOWLEDGE",
    "CONTROL_CENTER": "CURRENT_PROJECTION",
    "CONTINUITYOS_PROJECTION": "CURRENT_PROJECTION",
    "TWIN_NOMIC_768": "TWIN_OPERATIONAL",
}
MODE_AUTHORITY = {
    "DISCOVERY": frozenset({"RAW_EVIDENCE", "EVIDENCE_ONLY", "CURRENT_TRUTH", "OPERATIONAL_MEMORY"}),
    "EVIDENCE": frozenset({"RAW_EVIDENCE", "EVIDENCE_ONLY", "CURRENT_TRUTH"}),
    "CURRENT_STATE": frozenset({"CURRENT_TRUTH"}),
    "HISTORICAL_AS_OF": frozenset({"RAW_EVIDENCE", "EVIDENCE_ONLY", "CURRENT_TRUTH"}),
    "OPERATIONAL_RECALL": frozenset({"OPERATIONAL_MEMORY"}),
    "PHYSICAL_STATE": frozenset({"RAW_EVIDENCE", "EVIDENCE_ONLY", "CURRENT_TRUTH"}),
}
ADAPTER_ALLOWED_AUTHORITY = {
    "CHATGPT_LIBRARY_FILES": frozenset({"EVIDENCE_ONLY", "NONE"}),
    "GOOGLE_DRIVE_CONNECTOR": frozenset({"EVIDENCE_ONLY", "NONE"}),
    "ARCHIVEOS_RAW_CUSTODY": frozenset({"RAW_EVIDENCE", "EVIDENCE_ONLY", "NONE"}),
    "R1_4R_SQLITE_DIRECT": frozenset({"EVIDENCE_ONLY", "NONE"}),
    "ROBERT_MEMORY_ROUTER_V11": frozenset({"EVIDENCE_ONLY", "NONE"}),
    "POSTGRES_GOVERNED_FUTURE": frozenset({"EVIDENCE_ONLY", "NONE"}),
    "CONTROL_CENTER_CURRENT_PROJECTION": frozenset({"CURRENT_TRUTH", "NONE"}),
    "CONTINUITYOS_CURRENT_PROJECTION": frozenset({"CURRENT_TRUTH", "NONE"}),
    "TWIN_NOMIC_768": frozenset({"OPERATIONAL_MEMORY", "NONE"}),
    "REMOTE_MANUS_M01": frozenset({"NONE"}),
    "R4_MANUS_STAGING": frozenset({"EVIDENCE_ONLY", "NONE"}),
}
ADAPTER_PRIORITY = {
    "R1_4R_SQLITE_DIRECT": 10,
    "ROBERT_MEMORY_ROUTER_V11": 20,
    "CHATGPT_LIBRARY_FILES": 30,
    "GOOGLE_DRIVE_CONNECTOR": 30,
    "ARCHIVEOS_RAW_CUSTODY": 30,
    "POSTGRES_GOVERNED_FUTURE": 40,
    "CONTROL_CENTER_CURRENT_PROJECTION": 50,
    "CONTINUITYOS_CURRENT_PROJECTION": 50,
    "TWIN_NOMIC_768": 60,
    "REMOTE_MANUS_M01": 90,
    "R4_MANUS_STAGING": 90,
}
PHYSICAL_BINDINGS = frozenset({"DIRECT_PROVIDER_OBJECT", "DIRECT_LOCAL_RUNTIME", "RAW_BYTES"})
PHYSICAL_FRESHNESS = frozenset({"FRESH_PROVIDER", "FRESH_LOCAL_RUNTIME"})
MAX_CANDIDATES = 10_000
MAX_COVERAGE_ROWS = 1_000


class FederationContractError(ValueError):
    pass


def _time(value: Any, label: str, *, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    text = require_str(value, label)
    text = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise FederationContractError(f"{label} must be ISO/RFC3339 date-time") from exc
    if parsed.tzinfo is None:
        raise FederationContractError(f"{label} must be timezone-aware")
    return parsed


def _unique_strings(value: Any, label: str, maximum: int) -> tuple[str, ...]:
    rows = require_list(value, label, maximum)
    out = tuple(require_str(row, f"{label}[]") for row in rows)
    if len(out) != len(set(out)):
        raise FederationContractError(f"{label} must be unique")
    return out


def _exact_keys(obj: Mapping[str, Any], expected: set[str], label: str) -> None:
    missing = expected.difference(obj)
    extra = set(obj).difference(expected)
    if missing or extra:
        raise FederationContractError(
            f"{label} keys mismatch missing={sorted(missing)} extra={sorted(extra)}"
        )


QUERY_KEYS = {
    "schema", "query_id", "query", "resolution_mode", "scope",
    "as_of_valid_time", "observed_before_transaction_time",
    "source_classes", "project_ids", "include_conflicts", "include_superseded",
    "limit", "requested_effect", "created_at",
}
RESULT_KEYS = {
    "schema", "result_id", "query_id", "status", "surface", "stable_source_ref",
    "raw_artifact_ref", "provenance_chain", "valid_time", "transaction_time",
    "freshness", "confidence", "contradiction_state", "supersession_state",
    "authority_class", "payload", "abstain_reason", "effect_authority",
}
CANDIDATE_KEYS = {
    "candidate_id", "adapter_id", "semantic_key", "fact_class", "subject_ref",
    "payload_digest", "binding_strength", "source_occurrence_id", "result",
}


def validate_query(value: Mapping[str, Any]) -> dict[str, Any]:
    q = require_dict(value, "query")
    _exact_keys(q, QUERY_KEYS, "query")
    if q.get("schema") != QUERY_SCHEMA:
        raise FederationContractError(f"query.schema must be {QUERY_SCHEMA}")
    require_str(q.get("query_id"), "query.query_id")
    require_str(q.get("query"), "query.query")
    mode = require_str(q.get("resolution_mode"), "query.resolution_mode")
    if mode not in MODES:
        raise FederationContractError("unsupported resolution_mode")
    scopes = _unique_strings(q.get("scope"), "query.scope", len(SCOPES))
    if not scopes or any(scope not in SCOPES for scope in scopes):
        raise FederationContractError("unsupported query.scope")
    if q.get("as_of_valid_time") is not None:
        _time(q["as_of_valid_time"], "query.as_of_valid_time")
    if mode == "HISTORICAL_AS_OF" and q.get("as_of_valid_time") is None:
        raise FederationContractError("HISTORICAL_AS_OF requires as_of_valid_time")
    if q.get("observed_before_transaction_time") is not None:
        _time(q["observed_before_transaction_time"], "query.observed_before_transaction_time")
    _unique_strings(q.get("source_classes"), "query.source_classes", 500)
    _unique_strings(q.get("project_ids"), "query.project_ids", 500)
    require_bool(q.get("include_conflicts"), "query.include_conflicts")
    require_bool(q.get("include_superseded"), "query.include_superseded")
    limit = q.get("limit")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
        raise FederationContractError("query.limit must be integer 1..200")
    if q.get("requested_effect") is not False:
        raise FederationContractError("query.requested_effect must be false")
    _time(q.get("created_at"), "query.created_at")
    return dict(q)


def validate_result(value: Mapping[str, Any], *, query_id: str | None = None) -> dict[str, Any]:
    r = require_dict(value, "result")
    _exact_keys(r, RESULT_KEYS, "result")
    if r.get("schema") != RESULT_SCHEMA:
        raise FederationContractError(f"result.schema must be {RESULT_SCHEMA}")
    require_str(r.get("result_id"), "result.result_id")
    rid = require_str(r.get("query_id"), "result.query_id")
    if query_id is not None and rid != query_id:
        raise FederationContractError("result.query_id mismatch")
    status = require_str(r.get("status"), "result.status")
    if status not in {"HIT", "CONFLICT", "ABSTAIN"}:
        raise FederationContractError("unsupported result.status")
    surface = require_str(r.get("surface"), "result.surface")
    if surface not in SURFACE_SCOPE and surface != "UNKNOWN":
        raise FederationContractError("unsupported result.surface")
    stable = r.get("stable_source_ref")
    if stable is not None:
        require_str(stable, "result.stable_source_ref")
    raw = r.get("raw_artifact_ref")
    if raw is not None:
        require_str(raw, "result.raw_artifact_ref")
    provenance = _unique_strings(r.get("provenance_chain"), "result.provenance_chain", 1000)
    valid = require_dict(r.get("valid_time"), "result.valid_time")
    _exact_keys(valid, {"start", "end"}, "result.valid_time")
    start = _time(valid.get("start"), "result.valid_time.start", optional=True)
    end = _time(valid.get("end"), "result.valid_time.end", optional=True)
    if start is not None and end is not None and end <= start:
        raise FederationContractError("valid_time.end must be after start")
    tx = require_dict(r.get("transaction_time"), "result.transaction_time")
    _exact_keys(tx, {"observed_at", "recorded_at"}, "result.transaction_time")
    _time(tx.get("observed_at"), "result.transaction_time.observed_at")
    _time(tx.get("recorded_at"), "result.transaction_time.recorded_at")
    if r.get("freshness") not in {
        "FRESH_PROVIDER", "FRESH_LOCAL_RUNTIME", "SEALED_HISTORICAL", "STALE", "UNPROVEN"
    }:
        raise FederationContractError("unsupported freshness")
    confidence = r.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        raise FederationContractError("confidence must be 0..1")
    if r.get("contradiction_state") not in {
        "NONE_KNOWN", "CONFLICT_PRESENT", "SEARCH_INCOMPLETE", "UNPROVEN"
    }:
        raise FederationContractError("unsupported contradiction_state")
    if r.get("supersession_state") not in {
        "CURRENT", "SUPERSEDED", "HISTORICAL", "CANDIDATE", "UNPROVEN"
    }:
        raise FederationContractError("unsupported supersession_state")
    authority = r.get("authority_class")
    if authority not in {"RAW_EVIDENCE", "EVIDENCE_ONLY", "CURRENT_TRUTH", "OPERATIONAL_MEMORY", "NONE"}:
        raise FederationContractError("unsupported authority_class")
    if r.get("effect_authority") != "NONE":
        raise FederationContractError("effect_authority must be NONE")
    abstain_reason = r.get("abstain_reason")
    if status == "ABSTAIN":
        require_str(abstain_reason, "result.abstain_reason")
        if authority != "NONE":
            raise FederationContractError("ABSTAIN authority_class must be NONE")
    else:
        if stable is None or not provenance:
            raise FederationContractError("HIT/CONFLICT requires stable source and provenance")
        if abstain_reason is not None:
            raise FederationContractError("HIT/CONFLICT abstain_reason must be null")
    if status == "CONFLICT" and r.get("contradiction_state") != "CONFLICT_PRESENT":
        raise FederationContractError("CONFLICT requires contradiction_state=CONFLICT_PRESENT")
    return dict(r)


def _payload_digest(payload: Any) -> str:
    canonical = canonical_json_text(payload)
    if canonical.endswith("\n"):
        canonical = canonical[:-1]
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_candidate(value: Mapping[str, Any], *, query_id: str | None = None) -> dict[str, Any]:
    c = require_dict(value, "candidate")
    _exact_keys(c, CANDIDATE_KEYS, "candidate")
    require_str(c.get("candidate_id"), "candidate.candidate_id")
    adapter_id = require_str(c.get("adapter_id"), "candidate.adapter_id")
    if adapter_id not in ADAPTER_ALLOWED_AUTHORITY:
        raise FederationContractError(f"unregistered adapter_id: {adapter_id}")
    require_str(c.get("semantic_key"), "candidate.semantic_key")
    if c.get("fact_class") not in {"PHYSICAL", "SEMANTIC", "PREFERENCE", "HISTORICAL", "DISCOVERY"}:
        raise FederationContractError("unsupported fact_class")
    require_str(c.get("subject_ref"), "candidate.subject_ref")
    digest = require_sha(c.get("payload_digest"), "candidate.payload_digest")
    binding = c.get("binding_strength")
    if binding not in {
        "DIRECT_PROVIDER_OBJECT", "DIRECT_LOCAL_RUNTIME", "RAW_BYTES",
        "IMMUTABLE_RECEIPT", "NORMALIZED_EVIDENCE", "PROJECTION",
        "OPERATIONAL_MEMORY", "UNBOUND",
    }:
        raise FederationContractError("unsupported binding_strength")
    require_str(c.get("source_occurrence_id"), "candidate.source_occurrence_id")
    r = validate_result(c.get("result"), query_id=query_id)
    if r["authority_class"] not in ADAPTER_ALLOWED_AUTHORITY[adapter_id]:
        raise FederationContractError(
            f"{adapter_id} may not emit authority_class={r['authority_class']}"
        )
    if r["status"] != "ABSTAIN" and digest != _payload_digest(r["payload"]):
        raise FederationContractError("candidate.payload_digest does not match result.payload")
    return dict(c)


def _sort_key(c: Mapping[str, Any]) -> tuple[Any, ...]:
    r = c["result"]
    return (
        c["semantic_key"],
        ADAPTER_PRIORITY[c["adapter_id"]],
        r.get("stable_source_ref") or "",
        c["candidate_id"],
    )


def _time_eligible(q: Mapping[str, Any], c: Mapping[str, Any]) -> tuple[bool, str | None]:
    r = c["result"]
    cutoff = q.get("observed_before_transaction_time")
    if cutoff is not None and _time(r["transaction_time"]["recorded_at"], "recorded_at") > _time(cutoff, "cutoff"):
        return False, "TRANSACTION_TIME_AFTER_CUTOFF"
    if q["resolution_mode"] == "HISTORICAL_AS_OF":
        as_of = _time(q["as_of_valid_time"], "as_of_valid_time")
        start = _time(r["valid_time"]["start"], "valid_time.start", optional=True)
        end = _time(r["valid_time"]["end"], "valid_time.end", optional=True)
        if start is None:
            return False, "VALID_TIME_START_UNPROVEN"
        if as_of < start or (end is not None and as_of >= end):
            return False, "OUTSIDE_VALID_TIME"
    return True, None


def _eligible(q: Mapping[str, Any], c: Mapping[str, Any]) -> tuple[bool, str | None]:
    r = c["result"]
    if r["surface"] == "UNKNOWN" or SURFACE_SCOPE[r["surface"]] not in q["scope"]:
        return False, "OUT_OF_SCOPE"
    if r["status"] == "ABSTAIN":
        return False, "CANDIDATE_ABSTAIN"
    mode = q["resolution_mode"]
    if r["authority_class"] not in MODE_AUTHORITY[mode]:
        return False, "AUTHORITY_INCOMPATIBLE"
    if not q["include_superseded"] and mode not in {"HISTORICAL_AS_OF", "DISCOVERY", "EVIDENCE"}:
        if r["supersession_state"] in {"SUPERSEDED", "HISTORICAL"}:
            return False, "SUPERSEDED_OR_HISTORICAL"
    if mode == "CURRENT_STATE":
        if r["supersession_state"] != "CURRENT":
            return False, "CURRENT_STATE_REQUIRES_CURRENT_SUPERSESSION"
        if r["freshness"] in {"STALE", "UNPROVEN"}:
            return False, "CURRENT_STATE_FRESHNESS_UNPROVEN"
    if mode == "PHYSICAL_STATE":
        if c["fact_class"] != "PHYSICAL":
            return False, "PHYSICAL_MODE_REQUIRES_PHYSICAL_FACT"
        if c["binding_strength"] not in PHYSICAL_BINDINGS:
            return False, "PHYSICAL_MODE_REQUIRES_DIRECT_BINDING"
        if r["freshness"] not in PHYSICAL_FRESHNESS:
            return False, "PHYSICAL_MODE_REQUIRES_FRESH_DIRECT_READBACK"
    if mode == "OPERATIONAL_RECALL" and c["binding_strength"] != "OPERATIONAL_MEMORY":
        return False, "OPERATIONAL_MODE_REQUIRES_OPERATIONAL_BINDING"
    return _time_eligible(q, c)


def resolve_candidates(
    query: Mapping[str, Any],
    candidates: Iterable[Mapping[str, Any]],
    *,
    sources_unavailable: Iterable[str] = (),
    coverage_limits: Iterable[str] = (),
) -> dict[str, Any]:
    """Pure deterministic fan-in; conflict detection precedes result limiting."""
    q = validate_query(query)
    raw = tuple(candidates)
    if len(raw) > MAX_CANDIDATES:
        raise FederationContractError("too many candidates")
    validated = tuple(validate_candidate(c, query_id=q["query_id"]) for c in raw)
    unavailable = _unique_strings(list(sources_unavailable), "sources_unavailable", MAX_COVERAGE_ROWS)
    limits = _unique_strings(list(coverage_limits), "coverage_limits", MAX_COVERAGE_ROWS)

    discarded: list[dict[str, str]] = []
    eligible: list[dict[str, Any]] = []
    for c in validated:
        ok, reason = _eligible(q, c)
        if not ok:
            discarded.append({"candidate_id": c["candidate_id"], "reason": str(reason)})
            continue
        eligible.append(c)

    aliases: dict[tuple[str, str, str | None, str, str], dict[str, Any]] = {}
    for c in sorted(eligible, key=_sort_key):
        r = c["result"]
        key = (
            c["semantic_key"], c["payload_digest"], r.get("stable_source_ref"),
            r["authority_class"], c["source_occurrence_id"],
        )
        if key in aliases:
            discarded.append({"candidate_id": c["candidate_id"], "reason": "EXACT_RETRIEVAL_ALIAS"})
        else:
            aliases[key] = c
    eligible = list(aliases.values())

    by_key: dict[str, list[dict[str, Any]]] = {}
    for c in eligible:
        by_key.setdefault(c["semantic_key"], []).append(c)
    conflict_ids = [
        c["candidate_id"] for c in eligible
        if c["result"]["status"] == "CONFLICT"
    ]
    for group in by_key.values():
        if len({c["payload_digest"] for c in group}) > 1:
            conflict_ids.extend(c["candidate_id"] for c in group)

    if conflict_ids:
        decision, selected = "CONFLICT", []
        trace = ["FILTER", "ALIAS_COLLAPSE", "CONFLICT_BEFORE_LIMIT", "FAIL_CLOSED"]
    elif not eligible:
        decision, selected = "ABSTAIN", []
        trace = ["FILTER", "NO_ELIGIBLE_CANDIDATE", "ABSTAIN"]
    else:
        decision = "HIT"
        selected = [c["candidate_id"] for c in sorted(eligible, key=_sort_key)[:q["limit"]]]
        trace = ["FILTER", "ALIAS_COLLAPSE", "CONFLICT_BEFORE_LIMIT", "SORT", "LIMIT_LAST"]

    digest_input = {
        "query": q,
        "candidates": sorted(validated, key=lambda c: c["candidate_id"]),
        "sources_unavailable": sorted(unavailable),
        "coverage_limits": sorted(limits),
    }
    digest = hashlib.sha256(canonical_json_text(digest_input).encode("utf-8")).hexdigest()
    coverage = "PARTIAL" if unavailable or limits else ("UNKNOWN" if not validated else "COMPLETE")
    return {
        "schema": RESOLUTION_SCHEMA,
        "query_id": q["query_id"],
        "decision": decision,
        "coverage_status": coverage,
        "selected_candidate_ids": selected,
        "conflict_candidate_ids": sorted(set(conflict_ids)),
        "discarded": sorted(discarded, key=lambda row: (row["candidate_id"], row["reason"])),
        "eligible_before_limit": len(eligible),
        "sources_unavailable": sorted(unavailable),
        "coverage_limits": sorted(limits),
        "rule_trace": trace,
        "canonical_input_digest": digest,
        "effect_authority": "NONE",
        "authority": {
            "resolver_grants_current_truth": False,
            "resolver_grants_effect_authority": False,
            "can_trade": False,
            "capital_permission": "DENY",
        },
    }


@runtime_checkable
class ReadOnlyFederationAdapter(Protocol):
    adapter_id: str

    def query(self, query: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        ...


@dataclass(frozen=True)
class StaticAdapter:
    adapter_id: str
    candidates: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        if self.adapter_id not in ADAPTER_ALLOWED_AUTHORITY:
            raise FederationContractError(f"unregistered adapter_id: {self.adapter_id}")

    def query(self, query: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        q = validate_query(query)
        return tuple(c for c in self.candidates if c.get("result", {}).get("query_id") == q["query_id"])


@dataclass(frozen=True)
class FederationReadResult:
    resolution: Mapping[str, Any]
    response: Mapping[str, Any]
    candidates: tuple[Mapping[str, Any], ...]


class MemoryFederation:
    """Read-only adapter fan-in. There is intentionally no write/effect method."""

    def __init__(self, adapters: Sequence[ReadOnlyFederationAdapter]):
        ids = [require_str(adapter.adapter_id, "adapter.adapter_id") for adapter in adapters]
        if len(ids) != len(set(ids)):
            raise FederationContractError("adapter_id values must be unique")
        if any(adapter_id not in ADAPTER_ALLOWED_AUTHORITY for adapter_id in ids):
            raise FederationContractError("all adapters must be registered in capability policy")
        self._adapters = tuple(adapters)

    @property
    def adapter_ids(self) -> tuple[str, ...]:
        return tuple(adapter.adapter_id for adapter in self._adapters)

    def read(
        self,
        query: Mapping[str, Any],
        *,
        unavailable_adapters: Iterable[str] = (),
        coverage_limits: Iterable[str] = (),
    ) -> FederationReadResult:
        q = validate_query(query)
        unavailable = set(unavailable_adapters)
        limits = tuple(coverage_limits)
        unknown = unavailable.difference(self.adapter_ids)
        if unknown:
            raise FederationContractError("unknown unavailable adapters: " + ",".join(sorted(unknown)))
        candidates: list[Mapping[str, Any]] = []
        consulted: list[str] = []
        for adapter in self._adapters:
            if adapter.adapter_id in unavailable:
                continue
            consulted.append(adapter.adapter_id)
            rows = adapter.query(q)
            for row in rows:
                if row.get("adapter_id") != adapter.adapter_id:
                    raise FederationContractError("adapter emitted candidate under different adapter_id")
            candidates.extend(rows)

        resolution = resolve_candidates(
            q, candidates,
            sources_unavailable=sorted(unavailable),
            coverage_limits=limits,
        )
        if resolution["decision"] == "ABSTAIN":
            gateway_status = "ABSTAIN"
            results: list[dict[str, Any]] = []
        else:
            gateway_status = (
                "PARTIAL" if resolution["coverage_status"] == "PARTIAL"
                else "PASS_WITH_CONDITIONS" if resolution["decision"] == "CONFLICT"
                else "PASS"
            )
            selected_ids = set(resolution["selected_candidate_ids"])
            conflict_ids = set(resolution["conflict_candidate_ids"])
            results = []
            for candidate in sorted(candidates, key=_sort_key):
                cid = candidate["candidate_id"]
                if cid not in selected_ids and cid not in conflict_ids:
                    continue
                result = dict(candidate["result"])
                if cid in conflict_ids:
                    result["status"] = "CONFLICT"
                    result["contradiction_state"] = "CONFLICT_PRESENT"
                results.append(result)

        response = {
            "schema": RESPONSE_SCHEMA,
            "query_id": q["query_id"],
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "results": results,
            "gateway_status": gateway_status,
            "sources_consulted": sorted(consulted),
            "sources_unavailable": sorted(unavailable),
            "coverage_limits": sorted(set(limits)),
            "authority": {
                "read_only": True,
                "grants_current_truth": False,
                "grants_effect_authority": False,
                "can_trade": False,
                "capital_permission": "DENY",
            },
        }
        return FederationReadResult(resolution=resolution, response=response, candidates=tuple(candidates))
