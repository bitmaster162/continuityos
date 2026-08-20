from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any, Mapping, Sequence

from .canon import sha256_obj
from .errors import EvidenceError

ARM_B_BUILDER_SCHEMA = "sct.r13-arm-b-profile-rag-builder/v1"

PROFILE_POLICY = {
    "schema": "sct.r13-arm-b-profile-policy/v1",
    "source": "same_admitted_raw_pool_as_arm_c",
    "eligibility": "human_authored_profile_eligible_only",
    "assistant_authored": "forbidden",
    "sct_only_derived": "forbidden",
    "exact_dedup": "content_sha256",
    "order": ["observed_at_desc", "source_id_asc", "segment_id_asc"],
    "initial_context_fraction": 0.40,
}

RETRIEVAL_POLICY = {
    "schema": "sct.r13-arm-b-retrieval-policy/v1",
    "source": "same_admitted_raw_pool_as_arm_c",
    "query": "scenario_plus_options_unicode_word_tokens",
    "score": "unique_query_token_overlap_count",
    "tie_break": ["observed_at_desc", "source_id_asc", "segment_id_asc"],
    "semantic_embeddings": False,
    "learned_ranker": False,
    "assistant_authored": "forbidden",
    "sct_only_derived": "forbidden",
}

SOURCE_CUTOFF_POLICY = {
    "schema": "sct.r13-arm-b-source-cutoff/v1",
    "rule": "observed_at_lte_frozen_source_cutoff",
    "post_cutoff_evidence": "forbidden",
    "future_information": "forbidden",
}

CONTEXT_SELECTION_POLICY = {
    "schema": "sct.r13-arm-b-context-selection/v1",
    "payload_parity_ratio": 1.15,
    "initial_profile_fraction": 0.40,
    "spill_unused_profile_budget_to_retrieval": True,
    "spill_unused_retrieval_budget_to_profile": True,
    "whole_segments_preferred": True,
    "final_segment_utf8_prefix_truncation_allowed": True,
    "provenance_header": "[source_id|segment_id|observed_at]",
    "selection_is_deterministic": True,
}


def baseline_policy_hashes() -> dict[str, str]:
    return {
        "profile_builder_sha256": sha256_obj(PROFILE_POLICY),
        "retrieval_policy_sha256": sha256_obj(RETRIEVAL_POLICY),
        "source_cutoff_sha256": sha256_obj(SOURCE_CUTOFF_POLICY),
        "context_selection_policy_sha256": sha256_obj(CONTEXT_SELECTION_POLICY),
    }


@dataclass(frozen=True)
class AdmittedSegment:
    segment_id: str
    source_id: str
    text: str
    observed_at: float
    profile_eligible: bool
    content_sha256: str


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"Arm B segment requires non-empty {field}")
    return value.strip()


def _finite_time(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError("Arm B segment observed_at must be numeric")
    out = float(value)
    if not math.isfinite(out) or out <= 0:
        raise EvidenceError("Arm B segment observed_at must be positive finite")
    return out


def _admit_segment(row: Mapping[str, Any], *, source_cutoff: float) -> AdmittedSegment | None:
    if row.get("admitted") is not True:
        return None
    if row.get("assistant_authored") is not False:
        return None
    if row.get("sct_only_derived") is not False:
        return None
    authorship = row.get("authorship")
    if authorship not in {"HUMAN_USER", "OBSERVED_HUMAN_CHOICE"}:
        return None
    observed_at = _finite_time(row.get("observed_at"))
    if observed_at > source_cutoff:
        return None
    segment_id = _text(row.get("segment_id"), "segment_id")
    source_id = _text(row.get("source_id"), "source_id")
    text = _text(row.get("text"), "text")
    profile_eligible = row.get("profile_eligible") is True
    return AdmittedSegment(
        segment_id=segment_id,
        source_id=source_id,
        text=text,
        observed_at=observed_at,
        profile_eligible=profile_eligible,
        content_sha256=sha256_obj(text),
    )


def admitted_segments(rows: Sequence[Mapping[str, Any]], *, source_cutoff: float) -> tuple[AdmittedSegment, ...]:
    cutoff = _finite_time(source_cutoff)
    admitted: list[AdmittedSegment] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise EvidenceError("Arm B evidence rows must be objects")
        segment = _admit_segment(row, source_cutoff=cutoff)
        if segment is not None:
            admitted.append(segment)
    # Exact duplicate text contributes capacity only once. Prefer the most recent admissible occurrence,
    # then a stable provenance tie-break.
    admitted.sort(key=lambda x: (-x.observed_at, x.source_id, x.segment_id))
    deduped: list[AdmittedSegment] = []
    seen: set[str] = set()
    for segment in admitted:
        if segment.content_sha256 in seen:
            continue
        seen.add(segment.content_sha256)
        deduped.append(segment)
    return tuple(deduped)


def admitted_pool_sha256(segments: Sequence[AdmittedSegment]) -> str:
    rows = [
        {
            "segment_id": s.segment_id,
            "source_id": s.source_id,
            "observed_at": s.observed_at,
            "profile_eligible": s.profile_eligible,
            "content_sha256": s.content_sha256,
        }
        for s in segments
    ]
    return sha256_obj(rows)


def _tokens(text: str) -> frozenset[str]:
    return frozenset(token.casefold() for token in re.findall(r"[^\W_]+(?:[_-][^\W_]+)*|\d+", text, flags=re.UNICODE))


def _render(segment: AdmittedSegment) -> str:
    return f"[{segment.source_id}|{segment.segment_id}|{segment.observed_at:.6f}] {segment.text}"


def _utf8_prefix(text: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    return raw[:max_bytes].decode("utf-8", errors="ignore").rstrip()


def _pack(candidates: Sequence[AdmittedSegment], budget: int, *, used: set[str]) -> tuple[str, int]:
    if budget <= 0:
        return "", 0
    parts: list[str] = []
    consumed = 0
    for segment in candidates:
        if segment.content_sha256 in used:
            continue
        rendered = _render(segment)
        separator = 1 if parts else 0
        required = len(rendered.encode("utf-8")) + separator
        remaining = budget - consumed
        if required <= remaining:
            parts.append(rendered)
            used.add(segment.content_sha256)
            consumed += required
            continue
        allowance = remaining - separator
        if allowance > 24:
            clipped = _utf8_prefix(rendered, allowance)
            if clipped:
                parts.append(clipped)
                used.add(segment.content_sha256)
                consumed += separator + len(clipped.encode("utf-8"))
        break
    return "\n".join(parts), consumed


def build_arm_b_profile_rag(
    *,
    scenario: str,
    options: Sequence[str],
    evidence_rows: Sequence[Mapping[str, Any]],
    source_cutoff: float,
    target_context_bytes: int,
    expected_admitted_pool_sha256: str | None = None,
) -> dict[str, Any]:
    """Build the frozen strong Arm B without LLMs, embeddings, or SCT-derived claims.

    `evidence_rows` must represent the same admitted raw evidence pool available to Arm C at
    the frozen source cutoff. The optional expected pool hash makes that parity fail closed.
    """
    scenario = _text(scenario, "scenario")
    clean_options = tuple(dict.fromkeys(_text(x, "option") for x in options))
    if len(clean_options) < 2:
        raise EvidenceError("Arm B requires at least two distinct options")
    if isinstance(target_context_bytes, bool) or not isinstance(target_context_bytes, int) or target_context_bytes < 128:
        raise EvidenceError("Arm B target_context_bytes must be integer >= 128")

    segments = admitted_segments(evidence_rows, source_cutoff=source_cutoff)
    if not segments:
        raise EvidenceError("Arm B admitted evidence pool is empty")
    pool_sha = admitted_pool_sha256(segments)
    if expected_admitted_pool_sha256 is not None and expected_admitted_pool_sha256 != pool_sha:
        raise EvidenceError("Arm B admitted evidence pool SHA-256 mismatch")

    profile_candidates = tuple(s for s in segments if s.profile_eligible)
    query_tokens = _tokens(scenario + "\n" + "\n".join(clean_options))

    def retrieval_key(segment: AdmittedSegment):
        overlap = len(query_tokens.intersection(_tokens(segment.text)))
        return (-overlap, -segment.observed_at, segment.source_id, segment.segment_id)

    retrieval_candidates = tuple(sorted(segments, key=retrieval_key))
    profile_budget = int(target_context_bytes * float(PROFILE_POLICY["initial_context_fraction"]))
    history_budget = target_context_bytes - profile_budget - 1
    used: set[str] = set()
    static_profile, profile_used = _pack(profile_candidates, profile_budget, used=used)
    permitted_history, history_used = _pack(retrieval_candidates, history_budget, used=used)

    consumed = profile_used + history_used + (1 if static_profile and permitted_history else 0)
    remaining = target_context_bytes - consumed
    if remaining > 24:
        # Deterministic spill: retrieval first (strong query-conditioned baseline), then unused profile rows.
        spill, spill_used = _pack(retrieval_candidates, remaining, used=used)
        if spill:
            permitted_history = "\n".join(x for x in (permitted_history, spill) if x)
            history_used += spill_used
            consumed += spill_used + (1 if permitted_history and history_used == spill_used else 0)
            remaining = target_context_bytes - len((static_profile + ("\n" if static_profile and permitted_history else "") + permitted_history).encode("utf-8"))
        if remaining > 24:
            spill_profile, _ = _pack(profile_candidates, remaining, used=used)
            if spill_profile:
                static_profile = "\n".join(x for x in (static_profile, spill_profile) if x)

    combined = static_profile + ("\n" if static_profile and permitted_history else "") + permitted_history
    payload_bytes = len(combined.encode("utf-8"))
    if not static_profile:
        raise EvidenceError("Arm B strong baseline requires at least one profile-eligible human segment")
    if not permitted_history:
        raise EvidenceError("Arm B strong baseline requires non-empty retrieval history")
    if payload_bytes > target_context_bytes:
        raise EvidenceError("Arm B builder exceeded frozen context byte budget")

    return {
        "schema": ARM_B_BUILDER_SCHEMA,
        "static_profile": static_profile,
        "permitted_history": permitted_history,
        "payload_bytes": payload_bytes,
        "target_context_bytes": target_context_bytes,
        "source_cutoff": float(source_cutoff),
        "admitted_segment_count": len(segments),
        "admitted_pool_sha256": pool_sha,
        "query_sha256": sha256_obj({"scenario": scenario, "options": clean_options}),
        "policy_hashes": baseline_policy_hashes(),
        "assistant_authored_admitted": False,
        "sct_only_derived_admitted": False,
        "semantic_embeddings_used": False,
        "learned_ranker_used": False,
        "execution_authority": "NONE",
        "can_execute": False,
    }
