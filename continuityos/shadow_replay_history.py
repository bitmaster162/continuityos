from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Sequence

from .unified_shadow_continuity import REQUIRED_SAFETY, ShadowContinuityError, sha256_obj

REGISTRY_SCHEMA = "continuityos.shadow_replay_registry_snapshot.v1"
ADMISSION_SCHEMA = "continuityos.shadow_replay_admission_candidate.v1"
LEDGER_SCHEMA = "continuityos.shadow_case_ledger_snapshot.v1"
EVENT_SCHEMA = "continuityos.shadow_case_event.v1"
APPEND_SCHEMA = "continuityos.shadow_case_append_candidate.v1"

_EVENT_ORDER = {
    "CASE_QUALIFIED": 10,
    "TWIN_COMMITTED": 20,
    "DECISION_PACKET": 30,
    "HUMAN_REVEAL": 40,
    "OUTCOME_RECEIPT": 50,
    "RETURN_INTAKE": 60,
}
_UNIQUE_EVENT_TYPES = frozenset(_EVENT_ORDER)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ShadowContinuityError(f"{field}_required")
    return value.strip()


def _sha(value: Any, field: str) -> str:
    text = _text(value, field).lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ShadowContinuityError(f"{field}_must_be_sha256")
    return text


def _iso(value: Any, field: str) -> str:
    text = _text(value, field)
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError as exc:
        raise ShadowContinuityError(f"{field}_must_be_iso8601") from exc
    if parsed.tzinfo is None:
        raise ShadowContinuityError(f"{field}_timezone_required")
    return text


def _safe(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ShadowContinuityError(f"{field}_missing")
    for key, expected in REQUIRED_SAFETY.items():
        if value.get(key) != expected or type(value.get(key)) is not type(expected):
            raise ShadowContinuityError(f"unsafe_{field}:{key}")
    return dict(REQUIRED_SAFETY)


def _verify_hash(record: Mapping[str, Any], field: str, code: str) -> str:
    if not isinstance(record, Mapping):
        raise ShadowContinuityError(code)
    supplied = _sha(record.get(field), field)
    expected = sha256_obj({k: v for k, v in record.items() if k != field})
    if supplied != expected:
        raise ShadowContinuityError(code)
    return supplied


def build_empty_replay_registry(*, registry_id: str, authority_root_sha256: str) -> dict[str, Any]:
    body = {
        "schema": REGISTRY_SCHEMA,
        "registry_id": _text(registry_id, "registry_id"),
        "authority_root_sha256": _sha(authority_root_sha256, "authority_root_sha256"),
        "entries": (),
        "entry_count": 0,
        "write_allowed": False,
        "apply_allowed": False,
        "safety": dict(REQUIRED_SAFETY),
    }
    body["registry_sha256"] = sha256_obj(body)
    return body


def validate_replay_registry(
    registry: Mapping[str, Any],
    *,
    expected_registry_sha256: str,
    expected_authority_root_sha256: str,
) -> dict[str, Any]:
    if not isinstance(registry, Mapping) or registry.get("schema") != REGISTRY_SCHEMA:
        raise ShadowContinuityError("replay_registry_schema_mismatch")
    _safe(registry.get("safety", {}), "replay_registry_safety")
    registry_sha = _verify_hash(registry, "registry_sha256", "replay_registry_hash_mismatch")
    if registry_sha != _sha(expected_registry_sha256, "expected_registry_sha256"):
        raise ShadowContinuityError("replay_registry_external_snapshot_mismatch")
    if registry.get("authority_root_sha256") != _sha(expected_authority_root_sha256, "expected_authority_root_sha256"):
        raise ShadowContinuityError("replay_registry_authority_root_mismatch")
    if registry.get("write_allowed") is not False or registry.get("apply_allowed") is not False:
        raise ShadowContinuityError("replay_registry_effect_boundary_breached")

    entries = registry.get("entries")
    if not isinstance(entries, (list, tuple)):
        raise ShadowContinuityError("replay_registry_entries_invalid")
    seen_cases: set[str] = set()
    seen_case_hashes: set[str] = set()
    seen_bindings: set[str] = set()
    seen_ledgers: set[str] = set()
    clean_entries: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ShadowContinuityError("replay_registry_entry_invalid")
        clean = {
            "case_id": _text(entry.get("case_id"), "registry.case_id"),
            "case_sha256": _sha(entry.get("case_sha256"), "registry.case_sha256"),
            "case_binding_sha256": _sha(entry.get("case_binding_sha256"), "registry.case_binding_sha256"),
            "replay_input_sha256": _sha(entry.get("replay_input_sha256"), "registry.replay_input_sha256"),
            "ledger_id": _text(entry.get("ledger_id"), "registry.ledger_id"),
        }
        if clean["case_id"] in seen_cases:
            raise ShadowContinuityError("replay_registry_duplicate_case_id")
        if clean["case_sha256"] in seen_case_hashes:
            raise ShadowContinuityError("replay_registry_duplicate_case_hash")
        if clean["case_binding_sha256"] in seen_bindings:
            raise ShadowContinuityError("replay_registry_duplicate_case_binding")
        if clean["ledger_id"] in seen_ledgers:
            raise ShadowContinuityError("replay_registry_duplicate_ledger_id")
        seen_cases.add(clean["case_id"])
        seen_case_hashes.add(clean["case_sha256"])
        seen_bindings.add(clean["case_binding_sha256"])
        seen_ledgers.add(clean["ledger_id"])
        clean_entries.append(clean)
    if registry.get("entry_count") != len(clean_entries):
        raise ShadowContinuityError("replay_registry_entry_count_mismatch")
    return dict(registry)


def build_replay_admission_candidate(
    registry: Mapping[str, Any],
    *,
    expected_registry_sha256: str,
    expected_authority_root_sha256: str,
    case_id: str,
    case_sha256: str,
    case_binding_sha256: str,
    replay_input_sha256: str,
    ledger_id: str,
) -> dict[str, Any]:
    current = validate_replay_registry(
        registry,
        expected_registry_sha256=expected_registry_sha256,
        expected_authority_root_sha256=expected_authority_root_sha256,
    )
    case_id_clean = _text(case_id, "case_id")
    case_sha = _sha(case_sha256, "case_sha256")
    binding_sha = _sha(case_binding_sha256, "case_binding_sha256")
    replay_sha = _sha(replay_input_sha256, "replay_input_sha256")
    ledger_id_clean = _text(ledger_id, "ledger_id")

    for entry in current["entries"]:
        if entry["case_binding_sha256"] == binding_sha:
            raise ShadowContinuityError("duplicate_replay_case_binding")
        if entry["case_sha256"] == case_sha and entry["case_id"] != case_id_clean:
            raise ShadowContinuityError("case_alias_replay_detected")
        if entry["case_id"] == case_id_clean and entry["case_binding_sha256"] != binding_sha:
            raise ShadowContinuityError("case_history_fork_detected")
        if entry["ledger_id"] == ledger_id_clean:
            raise ShadowContinuityError("ledger_id_reuse_detected")

    proposed_entry = {
        "case_id": case_id_clean,
        "case_sha256": case_sha,
        "case_binding_sha256": binding_sha,
        "replay_input_sha256": replay_sha,
        "ledger_id": ledger_id_clean,
    }
    next_entries = tuple([*current["entries"], proposed_entry])
    next_registry = {
        "schema": REGISTRY_SCHEMA,
        "registry_id": current["registry_id"],
        "authority_root_sha256": current["authority_root_sha256"],
        "entries": next_entries,
        "entry_count": len(next_entries),
        "write_allowed": False,
        "apply_allowed": False,
        "safety": dict(REQUIRED_SAFETY),
    }
    next_registry["registry_sha256"] = sha256_obj(next_registry)
    body = {
        "schema": ADMISSION_SCHEMA,
        "prior_registry_sha256": current["registry_sha256"],
        "case_id": case_id_clean,
        "case_sha256": case_sha,
        "case_binding_sha256": binding_sha,
        "replay_input_sha256": replay_sha,
        "ledger_id": ledger_id_clean,
        "status": "ADMITTABLE_NEW_CASE_SHADOW_ONLY",
        "next_registry_candidate": next_registry,
        "registry_write_performed": False,
        "apply_allowed": False,
        "execution_authority": "NONE",
        "safety": dict(REQUIRED_SAFETY),
    }
    body["admission_candidate_sha256"] = sha256_obj(body)
    return body


def build_empty_case_ledger(
    *,
    ledger_id: str,
    case_id: str,
    case_sha256: str,
    case_binding_sha256: str,
    genesis_sha256: str,
) -> dict[str, Any]:
    body = {
        "schema": LEDGER_SCHEMA,
        "ledger_id": _text(ledger_id, "ledger_id"),
        "case_id": _text(case_id, "case_id"),
        "case_sha256": _sha(case_sha256, "case_sha256"),
        "case_binding_sha256": _sha(case_binding_sha256, "case_binding_sha256"),
        "genesis_sha256": _sha(genesis_sha256, "genesis_sha256"),
        "events": (),
        "event_count": 0,
        "head_event_sha256": _sha(genesis_sha256, "genesis_sha256"),
        "human_reveal_count": 0,
        "outcome_count": 0,
        "return_intake_count": 0,
        "write_allowed": False,
        "apply_allowed": False,
        "safety": dict(REQUIRED_SAFETY),
    }
    body["ledger_sha256"] = sha256_obj(body)
    return body


def validate_case_ledger(
    ledger: Mapping[str, Any],
    *,
    expected_ledger_sha256: str,
    expected_head_event_sha256: str,
) -> dict[str, Any]:
    if not isinstance(ledger, Mapping) or ledger.get("schema") != LEDGER_SCHEMA:
        raise ShadowContinuityError("case_ledger_schema_mismatch")
    _safe(ledger.get("safety", {}), "case_ledger_safety")
    ledger_sha = _verify_hash(ledger, "ledger_sha256", "case_ledger_hash_mismatch")
    if ledger_sha != _sha(expected_ledger_sha256, "expected_ledger_sha256"):
        raise ShadowContinuityError("case_ledger_external_snapshot_mismatch")
    if ledger.get("write_allowed") is not False or ledger.get("apply_allowed") is not False:
        raise ShadowContinuityError("case_ledger_effect_boundary_breached")

    ledger_id = _text(ledger.get("ledger_id"), "ledger_id")
    case_id = _text(ledger.get("case_id"), "case_id")
    case_sha = _sha(ledger.get("case_sha256"), "case_sha256")
    case_binding = _sha(ledger.get("case_binding_sha256"), "case_binding_sha256")
    genesis = _sha(ledger.get("genesis_sha256"), "genesis_sha256")
    events = ledger.get("events")
    if not isinstance(events, (list, tuple)):
        raise ShadowContinuityError("case_ledger_events_invalid")

    previous = genesis
    last_order = 0
    seen_types: set[str] = set()
    seen_idempotency: set[str] = set()
    seen_subjects: set[tuple[str, str]] = set()
    reveal_count = 0
    outcome_count = 0
    return_count = 0
    for index, event in enumerate(events, start=1):
        if not isinstance(event, Mapping) or event.get("schema") != EVENT_SCHEMA:
            raise ShadowContinuityError("case_event_schema_mismatch")
        _safe(event.get("safety", {}), "case_event_safety")
        _verify_hash(event, "event_sha256", "case_event_hash_mismatch")
        if event.get("sequence") != index:
            raise ShadowContinuityError("case_event_sequence_mismatch")
        if event.get("ledger_id") != ledger_id or event.get("case_id") != case_id:
            raise ShadowContinuityError("case_event_identity_mismatch")
        if event.get("case_sha256") != case_sha or event.get("case_binding_sha256") != case_binding:
            raise ShadowContinuityError("case_event_case_binding_mismatch")
        if event.get("previous_event_sha256") != previous:
            raise ShadowContinuityError("case_event_chain_fork_detected")
        event_type = _text(event.get("event_type"), "event_type")
        if event_type not in _EVENT_ORDER:
            raise ShadowContinuityError("case_event_type_unsupported")
        order = _EVENT_ORDER[event_type]
        if order <= last_order:
            raise ShadowContinuityError("case_event_order_regression")
        if event_type in seen_types:
            raise ShadowContinuityError("case_event_type_duplicate")
        idem = _text(event.get("idempotency_key"), "idempotency_key")
        if idem in seen_idempotency:
            raise ShadowContinuityError("case_event_idempotency_duplicate")
        subject = _sha(event.get("subject_sha256"), "subject_sha256")
        subject_key = (event_type, subject)
        if subject_key in seen_subjects:
            raise ShadowContinuityError("case_event_subject_duplicate")
        _iso(event.get("recorded_at"), "recorded_at")
        if event.get("write_allowed") is not False or event.get("apply_allowed") is not False:
            raise ShadowContinuityError("case_event_effect_boundary_breached")

        seen_types.add(event_type)
        seen_idempotency.add(idem)
        seen_subjects.add(subject_key)
        last_order = order
        previous = str(event["event_sha256"])
        reveal_count += int(event_type == "HUMAN_REVEAL")
        outcome_count += int(event_type == "OUTCOME_RECEIPT")
        return_count += int(event_type == "RETURN_INTAKE")

    if outcome_count and not reveal_count:
        raise ShadowContinuityError("outcome_without_human_reveal")
    if return_count and not outcome_count:
        raise ShadowContinuityError("return_without_outcome")
    if ledger.get("event_count") != len(events):
        raise ShadowContinuityError("case_ledger_event_count_mismatch")
    if ledger.get("head_event_sha256") != previous:
        raise ShadowContinuityError("case_ledger_head_mismatch")
    if ledger.get("head_event_sha256") != _sha(expected_head_event_sha256, "expected_head_event_sha256"):
        raise ShadowContinuityError("case_ledger_external_head_mismatch")
    if ledger.get("human_reveal_count") != reveal_count:
        raise ShadowContinuityError("case_ledger_reveal_count_mismatch")
    if ledger.get("outcome_count") != outcome_count:
        raise ShadowContinuityError("case_ledger_outcome_count_mismatch")
    if ledger.get("return_intake_count") != return_count:
        raise ShadowContinuityError("case_ledger_return_count_mismatch")
    return dict(ledger)


def build_case_append_candidate(
    ledger: Mapping[str, Any],
    *,
    expected_ledger_sha256: str,
    expected_head_event_sha256: str,
    event_type: str,
    subject_sha256: str,
    idempotency_key: str,
    recorded_at: str,
) -> dict[str, Any]:
    current = validate_case_ledger(
        ledger,
        expected_ledger_sha256=expected_ledger_sha256,
        expected_head_event_sha256=expected_head_event_sha256,
    )
    event_type_clean = _text(event_type, "event_type")
    if event_type_clean not in _EVENT_ORDER:
        raise ShadowContinuityError("case_event_type_unsupported")
    existing_types = tuple(str(event["event_type"]) for event in current["events"])
    if event_type_clean in _UNIQUE_EVENT_TYPES and event_type_clean in existing_types:
        if event_type_clean == "HUMAN_REVEAL":
            raise ShadowContinuityError("one_case_one_reveal_violation")
        if event_type_clean == "RETURN_INTAKE":
            raise ShadowContinuityError("duplicate_return_intake_detected")
        raise ShadowContinuityError("case_event_type_duplicate")
    if existing_types and _EVENT_ORDER[event_type_clean] <= _EVENT_ORDER[existing_types[-1]]:
        raise ShadowContinuityError("case_event_order_regression")
    if event_type_clean == "OUTCOME_RECEIPT" and "HUMAN_REVEAL" not in existing_types:
        raise ShadowContinuityError("outcome_without_human_reveal")
    if event_type_clean == "RETURN_INTAKE" and "OUTCOME_RECEIPT" not in existing_types:
        raise ShadowContinuityError("return_without_outcome")
    idem = _text(idempotency_key, "idempotency_key")
    if any(event.get("idempotency_key") == idem for event in current["events"]):
        raise ShadowContinuityError("case_event_idempotency_duplicate")

    event = {
        "schema": EVENT_SCHEMA,
        "ledger_id": current["ledger_id"],
        "case_id": current["case_id"],
        "case_sha256": current["case_sha256"],
        "case_binding_sha256": current["case_binding_sha256"],
        "sequence": current["event_count"] + 1,
        "previous_event_sha256": current["head_event_sha256"],
        "event_type": event_type_clean,
        "subject_sha256": _sha(subject_sha256, "subject_sha256"),
        "idempotency_key": idem,
        "recorded_at": _iso(recorded_at, "recorded_at"),
        "write_allowed": False,
        "apply_allowed": False,
        "safety": dict(REQUIRED_SAFETY),
    }
    event["event_sha256"] = sha256_obj(event)
    next_events = tuple([*current["events"], event])
    next_ledger = {
        **{k: v for k, v in current.items() if k not in {"events", "event_count", "head_event_sha256", "human_reveal_count", "outcome_count", "return_intake_count", "ledger_sha256"}},
        "events": next_events,
        "event_count": len(next_events),
        "head_event_sha256": event["event_sha256"],
        "human_reveal_count": current["human_reveal_count"] + int(event_type_clean == "HUMAN_REVEAL"),
        "outcome_count": current["outcome_count"] + int(event_type_clean == "OUTCOME_RECEIPT"),
        "return_intake_count": current["return_intake_count"] + int(event_type_clean == "RETURN_INTAKE"),
    }
    next_ledger["ledger_sha256"] = sha256_obj(next_ledger)
    body = {
        "schema": APPEND_SCHEMA,
        "prior_ledger_sha256": current["ledger_sha256"],
        "prior_head_event_sha256": current["head_event_sha256"],
        "event": event,
        "next_ledger_candidate": next_ledger,
        "status": "APPENDABLE_SHADOW_ONLY",
        "ledger_write_performed": False,
        "apply_allowed": False,
        "execution_authority": "NONE",
        "safety": dict(REQUIRED_SAFETY),
    }
    body["append_candidate_sha256"] = sha256_obj(body)
    return body
