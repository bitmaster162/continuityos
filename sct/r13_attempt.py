from __future__ import annotations

import math
from typing import Any, Mapping, Sequence

from .canon import sha256_obj
from .errors import EvidenceError
from .r13 import (
    R13_BASELINE_EVENT,
    R13_FAILURE_EVENT,
    R13_MODEL_EVENT,
    R13_PREFLIGHT_SCHEMA,
    R13_PROTOCOL_EVENT,
    R13_QUALIFIED_EVENT,
    R13_SENTINEL_SCHEMA,
    R13_VOID_SCHEMA,
)

R13_COMPONENT_ATTEMPT_STARTED_EVENT = "R13_COMPONENT_ATTEMPT_STARTED"
R13_COMPONENT_RECEIPT_EVENT = "R13_COMPONENT_RECEIPT_RECORDED"
R13_ATTESTATION_VERIFIED_EVENT = "R13_OPERATOR_ATTESTATION_VERIFIED"

R13_COMPONENTS = ("preflight", "context-sentinel", "stable-void")
R13_COMPONENT_EXPECTED_CALLS = {
    "preflight": 2,
    "context-sentinel": 18,
    "stable-void": 30,
}
R13_COMPONENT_SCHEMAS = {
    "preflight": R13_PREFLIGHT_SCHEMA,
    "context-sentinel": R13_SENTINEL_SCHEMA,
    "stable-void": R13_VOID_SCHEMA,
}
R13_COMPONENT_PASS_FIELDS = {
    "preflight": "deterministic",
    "context-sentinel": "satisfies_context_responsiveness_gate",
    "stable-void": "stable_void_pass",
}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _is_git_oid(value: Any) -> bool:
    return isinstance(value, str) and len(value) in {40, 64} and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _component_index(component: str) -> int:
    try:
        return R13_COMPONENTS.index(component)
    except ValueError as exc:
        raise EvidenceError(f"unknown R13 qualification component: {component}") from exc


def _events_for_binding(store, kind: str, *, protocol_sha: str, model_sha: str):
    return [
        e
        for e in store.query(kind=kind)
        if e.payload.get("protocol_manifest_sha256") == protocol_sha
        and e.payload.get("model_selection_manifest_sha256") == model_sha
    ]


def _require_sealed_run_inputs(store, *, protocol_sha: str, model_sha: str) -> None:
    if not _is_sha256(protocol_sha) or not _is_sha256(model_sha):
        raise EvidenceError("R13 attempt requires exact protocol/model SHA-256 bindings")
    protocols = list(store.query(kind=R13_PROTOCOL_EVENT))
    models = list(store.query(kind=R13_MODEL_EVENT))
    baselines = list(store.query(kind=R13_BASELINE_EVENT))
    if not protocols or protocols[-1].payload.get("manifest_sha256") != protocol_sha:
        raise EvidenceError("matching R13 protocol must be sealed before real qualification calls")
    if not models or models[-1].payload.get("model_selection_manifest_sha256") != model_sha:
        raise EvidenceError("matching R13 model selection must be sealed before real qualification calls")
    if not baselines or baselines[-1].payload.get("protocol_manifest_sha256") != protocol_sha:
        raise EvidenceError("strong Arm B baseline must be sealed before the first R13 real-model call")
    if list(store.query(kind="CASE_FROZEN")):
        raise EvidenceError("R13 qualification attempts must precede every LIVE case")
    if not store.verify().ok:
        raise EvidenceError("Evidence Store verification failed before R13 qualification attempt")


def _component_rows(store, *, protocol_sha: str, model_sha: str, component: str, kind: str):
    return [
        e
        for e in _events_for_binding(store, kind, protocol_sha=protocol_sha, model_sha=model_sha)
        if e.payload.get("component") == component
    ]


def start_r13_component_attempt(
    store,
    *,
    component: str,
    protocol_manifest_sha256: str,
    model_selection_manifest_sha256: str,
    source_code_sha: str,
    source_tree_sha: str,
) -> dict[str, Any]:
    """Persist the point-of-no-return before any real model/logit call.

    A started component can never be started again under the same protocol/model binding,
    even if the process crashes before a receipt is written. Recovery requires a new
    versioned protocol or a new predeclared model-selection binding.
    """
    index = _component_index(component)
    protocol_sha = protocol_manifest_sha256.lower()
    model_sha = model_selection_manifest_sha256.lower()
    if not _is_git_oid(source_code_sha) or not _is_git_oid(source_tree_sha):
        raise EvidenceError("R13 attempt requires exact source commit and source tree object IDs")
    source_code_sha = source_code_sha.lower()
    source_tree_sha = source_tree_sha.lower()
    _require_sealed_run_inputs(store, protocol_sha=protocol_sha, model_sha=model_sha)

    failures = _events_for_binding(store, R13_FAILURE_EVENT, protocol_sha=protocol_sha, model_sha=model_sha)
    if failures:
        raise EvidenceError("R13_TERMINAL_ATTEMPT_FAILED: new versioned protocol/model selection required")
    if _events_for_binding(store, R13_QUALIFIED_EVENT, protocol_sha=protocol_sha, model_sha=model_sha):
        raise EvidenceError("R13 qualification already passed for this protocol/model binding")

    starts = _events_for_binding(
        store, R13_COMPONENT_ATTEMPT_STARTED_EVENT, protocol_sha=protocol_sha, model_sha=model_sha
    )
    receipts = _events_for_binding(
        store, R13_COMPONENT_RECEIPT_EVENT, protocol_sha=protocol_sha, model_sha=model_sha
    )
    if any(e.payload.get("component") == component for e in starts + receipts):
        raise EvidenceError(f"R13 component {component} has already been attempted; rerun is forbidden")

    for previous in R13_COMPONENTS[:index]:
        rows = [e for e in receipts if e.payload.get("component") == previous]
        if len(rows) != 1 or rows[0].payload.get("component_pass") is not True:
            raise EvidenceError(f"R13 component {component} requires one recorded PASS for {previous}")
    for later in R13_COMPONENTS[index + 1 :]:
        if any(e.payload.get("component") == later for e in starts + receipts):
            raise EvidenceError("R13 qualification component order is inconsistent")

    bound_source_pairs = {
        (e.payload.get("source_code_sha"), e.payload.get("source_tree_sha"))
        for e in starts + receipts
    }
    if bound_source_pairs and bound_source_pairs != {(source_code_sha, source_tree_sha)}:
        raise EvidenceError("R13 source commit/tree changed inside a qualification attempt")

    payload = {
        "component": component,
        "component_index": index,
        "expected_calls": R13_COMPONENT_EXPECTED_CALLS[component],
        "protocol_manifest_sha256": protocol_sha,
        "model_selection_manifest_sha256": model_sha,
        "source_code_sha": source_code_sha,
        "source_tree_sha": source_tree_sha,
        "automatic_retry": False,
        "replacement_cases": 0,
        "replacement_models": 0,
        "valid_live_n": 0,
        "terminal_if_interrupted": True,
        "can_execute": False,
        "execution_authority": "NONE",
    }
    store.append(R13_COMPONENT_ATTEMPT_STARTED_EVENT, payload)
    return payload


def _validate_trace(receipt: Mapping[str, Any], *, expected_calls: int, require_complete: bool) -> tuple[list[dict[str, Any]], str]:
    trace = receipt.get("raw_logit_trace")
    if not isinstance(trace, Sequence) or isinstance(trace, (str, bytes, bytearray)):
        raise EvidenceError("R13 component receipt requires raw_logit_trace")
    rows = [dict(row) for row in trace if isinstance(row, Mapping)]
    if len(rows) != len(trace):
        raise EvidenceError("R13 raw_logit_trace entries must be objects")
    if require_complete and len(rows) != expected_calls:
        raise EvidenceError("R13 PASS receipt raw-logit trace cardinality mismatch")
    attempted = receipt.get("attempted_calls")
    if isinstance(attempted, bool) or not isinstance(attempted, int) or attempted < 1 or attempted > expected_calls:
        raise EvidenceError("R13 component receipt attempted_calls outside frozen budget")
    if len(rows) > attempted:
        raise EvidenceError("R13 raw-logit trace cannot exceed attempted call count")
    for ordinal, row in enumerate(rows, start=1):
        if row.get("ordinal") != ordinal:
            raise EvidenceError("R13 raw-logit trace ordinal mismatch")
        if not _is_sha256(row.get("request_sha256")):
            raise EvidenceError("R13 raw-logit trace missing exact request SHA-256")
        aliases = row.get("allowed_aliases")
        ids = row.get("allowed_alias_token_ids")
        logits = row.get("raw_allowed_token_logits")
        if not isinstance(aliases, Sequence) or isinstance(aliases, (str, bytes)) or len(aliases) < 2:
            raise EvidenceError("R13 raw-logit trace allowed_aliases invalid")
        aliases = tuple(str(x) for x in aliases)
        if len(set(aliases)) != len(aliases):
            raise EvidenceError("R13 raw-logit trace aliases must be unique")
        if not isinstance(ids, Mapping) or set(ids) != set(aliases):
            raise EvidenceError("R13 raw-logit trace token-ID binding incomplete")
        if not isinstance(logits, Mapping) or set(logits) != set(aliases):
            raise EvidenceError("R13 raw-logit trace logits incomplete")
        for alias in aliases:
            token_id = ids[alias]
            if isinstance(token_id, bool) or not isinstance(token_id, int) or token_id < 0:
                raise EvidenceError("R13 raw-logit trace token ID invalid")
            value = logits[alias]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise EvidenceError("R13 raw-logit trace contains non-finite logit")
        if row.get("execution_authority") != "NONE":
            raise EvidenceError("R13 raw-logit trace cannot carry execution authority")
    calculated = sha256_obj(rows)
    if receipt.get("raw_logit_trace_sha256") != calculated:
        raise EvidenceError("R13 raw-logit trace SHA-256 mismatch")
    return rows, calculated


def validate_r13_component_receipt(component: str, receipt: Mapping[str, Any]) -> dict[str, Any]:
    _component_index(component)
    expected_calls = R13_COMPONENT_EXPECTED_CALLS[component]
    if receipt.get("schema") != R13_COMPONENT_SCHEMAS[component]:
        raise EvidenceError(f"R13 {component} receipt schema mismatch")
    passed = receipt.get(R13_COMPONENT_PASS_FIELDS[component]) is True
    rows, trace_sha = _validate_trace(receipt, expected_calls=expected_calls, require_complete=passed)
    if passed and receipt.get("attempted_calls") != expected_calls:
        raise EvidenceError(f"R13 {component} PASS requires exactly {expected_calls} calls")
    if receipt.get("automatic_retry") is not False:
        raise EvidenceError("R13 automatic retry is forbidden")
    if int(receipt.get("replacement_cases", 0)) != 0 or int(receipt.get("replacement_models", 0)) != 0:
        raise EvidenceError("R13 replacement cases/models are forbidden")
    if int(receipt.get("valid_live_cases_added", -1)) != 0:
        raise EvidenceError("R13 qualification must keep valid LIVE n at zero")
    if receipt.get("execution_authority") != "NONE":
        raise EvidenceError("R13 component receipt cannot grant execution authority")
    protocol_sha = receipt.get("protocol_manifest_sha256")
    model_sha = receipt.get("model_selection_manifest_sha256")
    if not _is_sha256(protocol_sha) or not _is_sha256(model_sha):
        raise EvidenceError("R13 component receipt missing protocol/model binding")
    normalized = dict(receipt)
    normalized["raw_logit_trace"] = rows
    normalized["raw_logit_trace_sha256"] = trace_sha
    return normalized


def finish_r13_component_attempt(store, *, component: str, receipt: Mapping[str, Any]) -> dict[str, Any]:
    validated = validate_r13_component_receipt(component, receipt)
    protocol_sha = validated["protocol_manifest_sha256"]
    model_sha = validated["model_selection_manifest_sha256"]
    starts = _component_rows(
        store,
        protocol_sha=protocol_sha,
        model_sha=model_sha,
        component=component,
        kind=R13_COMPONENT_ATTEMPT_STARTED_EVENT,
    )
    existing = _component_rows(
        store,
        protocol_sha=protocol_sha,
        model_sha=model_sha,
        component=component,
        kind=R13_COMPONENT_RECEIPT_EVENT,
    )
    if len(starts) != 1:
        raise EvidenceError("R13 component receipt requires exactly one prior ATTEMPT_STARTED event")
    if existing:
        raise EvidenceError("R13 component receipt already recorded; rerun/replacement forbidden")
    start = starts[0].payload
    if start.get("expected_calls") != R13_COMPONENT_EXPECTED_CALLS[component]:
        raise EvidenceError("R13 component start call budget mismatch")

    passed = validated[R13_COMPONENT_PASS_FIELDS[component]] is True
    receipt_sha = sha256_obj(validated)
    payload = {
        "component": component,
        "component_index": _component_index(component),
        "component_pass": passed,
        "expected_calls": R13_COMPONENT_EXPECTED_CALLS[component],
        "attempted_calls": validated["attempted_calls"],
        "receipt_sha256": receipt_sha,
        "raw_logit_trace_sha256": validated["raw_logit_trace_sha256"],
        "protocol_manifest_sha256": protocol_sha,
        "model_selection_manifest_sha256": model_sha,
        "source_code_sha": start["source_code_sha"],
        "source_tree_sha": start["source_tree_sha"],
        "automatic_retry": False,
        "replacement_cases": 0,
        "replacement_models": 0,
        "valid_live_n": 0,
        "can_execute": False,
        "execution_authority": "NONE",
    }
    store.append(R13_COMPONENT_RECEIPT_EVENT, payload)
    if not passed:
        failure = {
            "component": component,
            "protocol_manifest_sha256": protocol_sha,
            "model_selection_manifest_sha256": model_sha,
            "source_code_sha": start["source_code_sha"],
            "source_tree_sha": start["source_tree_sha"],
            "component_receipt_sha256": receipt_sha,
            "failure_class": str(validated.get("failure_class") or f"{component.upper()}_SCIENTIFIC_GATE_FAILED"),
            "terminal": True,
            "requires_new_versioned_protocol_or_model_selection": True,
            "valid_live_n": 0,
            "can_execute": False,
            "execution_authority": "NONE",
        }
        store.append(R13_FAILURE_EVENT, failure)
    return payload


def record_r13_component_abort(
    store,
    *,
    component: str,
    protocol_manifest_sha256: str,
    model_selection_manifest_sha256: str,
    failure_class: str,
) -> dict[str, Any]:
    """Record a terminal transport/runtime abort after ATTEMPT_STARTED without retrying."""
    protocol_sha = protocol_manifest_sha256.lower()
    model_sha = model_selection_manifest_sha256.lower()
    existing = _events_for_binding(store, R13_FAILURE_EVENT, protocol_sha=protocol_sha, model_sha=model_sha)
    if existing:
        return dict(existing[-1].payload)
    starts = _component_rows(
        store,
        protocol_sha=protocol_sha,
        model_sha=model_sha,
        component=component,
        kind=R13_COMPONENT_ATTEMPT_STARTED_EVENT,
    )
    if len(starts) != 1:
        raise EvidenceError("R13 abort requires one recorded component ATTEMPT_STARTED event")
    start = starts[0].payload
    payload = {
        "component": component,
        "protocol_manifest_sha256": protocol_sha,
        "model_selection_manifest_sha256": model_sha,
        "source_code_sha": start["source_code_sha"],
        "source_tree_sha": start["source_tree_sha"],
        "failure_class": str(failure_class)[:160],
        "terminal": True,
        "requires_new_versioned_protocol_or_model_selection": True,
        "valid_live_n": 0,
        "can_execute": False,
        "execution_authority": "NONE",
    }
    store.append(R13_FAILURE_EVENT, payload)
    return payload


def require_recorded_r13_component_receipts(
    store,
    *,
    preflight: Mapping[str, Any],
    sentinel: Mapping[str, Any],
    stable_void: Mapping[str, Any],
    expected_source_sha: str,
    expected_source_tree_sha: str,
) -> dict[str, Any]:
    supplied = {
        "preflight": validate_r13_component_receipt("preflight", preflight),
        "context-sentinel": validate_r13_component_receipt("context-sentinel", sentinel),
        "stable-void": validate_r13_component_receipt("stable-void", stable_void),
    }
    for component, receipt in supplied.items():
        if receipt[R13_COMPONENT_PASS_FIELDS[component]] is not True:
            raise EvidenceError(f"R13 qualification requires recorded PASS for {component}")
    protocol_hashes = {r["protocol_manifest_sha256"] for r in supplied.values()}
    model_hashes = {r["model_selection_manifest_sha256"] for r in supplied.values()}
    if len(protocol_hashes) != 1 or len(model_hashes) != 1:
        raise EvidenceError("R13 qualification component bindings disagree")
    protocol_sha = next(iter(protocol_hashes))
    model_sha = next(iter(model_hashes))
    if not _is_git_oid(expected_source_sha) or not _is_git_oid(expected_source_tree_sha):
        raise EvidenceError("R13 qualification requires exact source commit/tree")
    expected_source = (expected_source_sha.lower(), expected_source_tree_sha.lower())
    failures = _events_for_binding(store, R13_FAILURE_EVENT, protocol_sha=protocol_sha, model_sha=model_sha)
    if failures:
        raise EvidenceError("R13 terminal failure already recorded for this protocol/model binding")

    rows = []
    for component in R13_COMPONENTS:
        events = _component_rows(
            store,
            protocol_sha=protocol_sha,
            model_sha=model_sha,
            component=component,
            kind=R13_COMPONENT_RECEIPT_EVENT,
        )
        if len(events) != 1:
            raise EvidenceError(f"R13 qualification requires exactly one recorded receipt for {component}")
        event = events[0]
        supplied_sha = sha256_obj(supplied[component])
        if event.payload.get("receipt_sha256") != supplied_sha or event.payload.get("component_pass") is not True:
            raise EvidenceError(f"R13 recorded receipt binding mismatch for {component}")
        if (event.payload.get("source_code_sha"), event.payload.get("source_tree_sha")) != expected_source:
            raise EvidenceError("R13 qualification source commit/tree mismatch with component attempt")
        rows.append(event)
    if [e.payload.get("component_index") for e in rows] != [0, 1, 2] or not (rows[0].seq < rows[1].seq < rows[2].seq):
        raise EvidenceError("R13 qualification component order is not preflight -> sentinel -> stable-void")
    if not store.verify().ok:
        raise EvidenceError("Evidence Store verification failed before R13 qualification")
    return {
        "protocol_manifest_sha256": protocol_sha,
        "model_selection_manifest_sha256": model_sha,
        "source_code_sha": expected_source[0],
        "source_tree_sha": expected_source[1],
        "preflight_receipt_sha256": rows[0].payload["receipt_sha256"],
        "sentinel_receipt_sha256": rows[1].payload["receipt_sha256"],
        "stable_void_receipt_sha256": rows[2].payload["receipt_sha256"],
        "valid_live_n": 0,
        "execution_authority": "NONE",
    }


def record_verified_r13_operator_attestation(store, validated_attestation: Mapping[str, Any]) -> dict[str, Any]:
    required = (
        "attestation_sha256",
        "protocol_manifest_sha256",
        "model_selection_manifest_sha256",
        "source_code_sha",
        "source_tree_sha",
        "preflight_receipt_sha256",
        "sentinel_receipt_sha256",
        "stable_void_receipt_sha256",
    )
    for field in required:
        if not isinstance(validated_attestation.get(field), str) or not validated_attestation.get(field):
            raise EvidenceError(f"verified R13 operator attestation missing {field}")
    if validated_attestation.get("valid_live_n") != 0:
        raise EvidenceError("verified R13 operator attestation requires valid LIVE n=0")
    if validated_attestation.get("execution_authority") != "NONE" or validated_attestation.get("can_execute") is not False:
        raise EvidenceError("verified R13 operator attestation cannot grant execution authority")
    protocol_sha = validated_attestation["protocol_manifest_sha256"]
    model_sha = validated_attestation["model_selection_manifest_sha256"]
    receipts = _events_for_binding(
        store, R13_COMPONENT_RECEIPT_EVENT, protocol_sha=protocol_sha, model_sha=model_sha
    )
    by_component = {e.payload.get("component"): e for e in receipts if e.payload.get("component_pass") is True}
    if set(by_component) != set(R13_COMPONENTS):
        raise EvidenceError("verified R13 operator attestation requires complete recorded component receipts")
    expected_receipts = {
        "preflight": validated_attestation["preflight_receipt_sha256"],
        "context-sentinel": validated_attestation["sentinel_receipt_sha256"],
        "stable-void": validated_attestation["stable_void_receipt_sha256"],
    }
    for component, digest in expected_receipts.items():
        if by_component[component].payload.get("receipt_sha256") != digest:
            raise EvidenceError("verified R13 operator attestation receipt binding mismatch")
    source = (validated_attestation["source_code_sha"], validated_attestation["source_tree_sha"])
    if any((e.payload.get("source_code_sha"), e.payload.get("source_tree_sha")) != source for e in by_component.values()):
        raise EvidenceError("verified R13 operator attestation source binding mismatch")
    existing = _events_for_binding(
        store, R13_ATTESTATION_VERIFIED_EVENT, protocol_sha=protocol_sha, model_sha=model_sha
    )
    if existing:
        if existing[-1].payload.get("attestation_sha256") != validated_attestation["attestation_sha256"]:
            raise EvidenceError("different R13 operator attestation already verified")
        return dict(existing[-1].payload)
    payload = {
        "attestation_sha256": validated_attestation["attestation_sha256"],
        "protocol_manifest_sha256": protocol_sha,
        "model_selection_manifest_sha256": model_sha,
        "source_code_sha": source[0],
        "source_tree_sha": source[1],
        "preflight_receipt_sha256": validated_attestation["preflight_receipt_sha256"],
        "sentinel_receipt_sha256": validated_attestation["sentinel_receipt_sha256"],
        "stable_void_receipt_sha256": validated_attestation["stable_void_receipt_sha256"],
        "content_verified": True,
        "valid_live_n": 0,
        "can_execute": False,
        "execution_authority": "NONE",
    }
    store.append(R13_ATTESTATION_VERIFIED_EVENT, payload)
    return payload


def r13_attempt_status(store) -> dict[str, Any]:
    starts = list(store.query(kind=R13_COMPONENT_ATTEMPT_STARTED_EVENT))
    receipts = list(store.query(kind=R13_COMPONENT_RECEIPT_EVENT))
    failures = list(store.query(kind=R13_FAILURE_EVENT))
    latest_protocol = list(store.query(kind=R13_PROTOCOL_EVENT))
    latest_model = list(store.query(kind=R13_MODEL_EVENT))
    protocol_sha = latest_protocol[-1].payload.get("manifest_sha256") if latest_protocol else None
    model_sha = latest_model[-1].payload.get("model_selection_manifest_sha256") if latest_model else None
    bound_starts = [e for e in starts if e.payload.get("protocol_manifest_sha256") == protocol_sha and e.payload.get("model_selection_manifest_sha256") == model_sha]
    bound_receipts = [e for e in receipts if e.payload.get("protocol_manifest_sha256") == protocol_sha and e.payload.get("model_selection_manifest_sha256") == model_sha]
    bound_failures = [e for e in failures if e.payload.get("protocol_manifest_sha256") == protocol_sha and e.payload.get("model_selection_manifest_sha256") == model_sha]
    return {
        "protocol_manifest_sha256": protocol_sha,
        "model_selection_manifest_sha256": model_sha,
        "started_components": [e.payload.get("component") for e in bound_starts],
        "recorded_components": [
            {"component": e.payload.get("component"), "pass": e.payload.get("component_pass"), "receipt_sha256": e.payload.get("receipt_sha256")}
            for e in bound_receipts
        ],
        "terminal_failure_recorded": bool(bound_failures),
        "rerun_allowed_for_same_binding": False if bound_starts or bound_failures else True,
        "valid_live_n": 0,
        "execution_authority": "NONE",
    }
