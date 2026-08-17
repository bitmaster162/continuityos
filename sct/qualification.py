from __future__ import annotations

from typing import Any, Mapping, Sequence

from .bench.envelope import build_standard_inputs, render_request
from .bench.predict import validate_probability_response
from .canon import sha256_obj
from .dryrun import run_real_model_void_dryrun
from .errors import EvidenceError

R12_CONTEXT_SCHEMA = "sct.r12-context-responsiveness/v1"
R12_VOID_SCHEMA = "sct.r12-stable-single-model-void/v1"
R12_QUALIFICATION_SCHEMA = "sct.r12-precase-qualification/v1"
R12_QUALIFIED_EVENT = "R12_QUALIFICATION_PASSED"
R12_ENROLLMENT_AUTH_EVENT = "CASE001_ENROLLMENT_AUTHORIZED"


def _clean_options(options: Sequence[str]) -> tuple[str, ...]:
    cleaned = tuple(dict.fromkeys(str(x).strip() for x in options if str(x).strip()))
    if len(cleaned) < 2:
        raise ValueError("R12 context sentinel requires at least two distinct options")
    return cleaned


def _synthetic_context(target: str) -> str:
    return (
        "SYNTHETIC QUALIFICATION ONLY. "
        f"SYNTHETIC_TARGET={target}. "
        "For this synthetic sentinel, the principal has an explicit stable preference "
        f"to choose {target} among the listed options. Use this fact only for this VOID qualification call."
    )


def run_context_responsiveness_sentinel(
    *,
    runner,
    provider: str,
    model: str,
    model_version: str,
    options: Sequence[str] = ("A", "B", "C"),
    token_budget: int = 512,
    temperature: float | None = 0.0,
    reasoning: str = "fixed",
) -> dict[str, Any]:
    """Verify that the exact model path responds to contradictory personal_context.

    This is a synthetic VOID qualification check, not evidence about the principal.
    It deliberately imposes no minimum probability gap or entropy threshold.
    """
    opts = _clean_options(options)
    targets = (opts[0], opts[-1])
    scenario = "Synthetic context-responsiveness sentinel: predict which listed option the synthetic principal will choose."
    plan = {
        "schema": R12_CONTEXT_SCHEMA,
        "provider": provider,
        "model": model,
        "model_version": model_version,
        "options": opts,
        "targets": targets,
        "token_budget": token_budget,
        "temperature": temperature,
        "reasoning": reasoning,
        "automatic_retry": False,
        "minimum_probability_gap_required": False,
        "execution_authority": "NONE",
    }
    plan_sha256 = sha256_obj(plan)
    results: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    envelope_hashes: list[str] = []

    for ordinal, target in enumerate(targets, start=1):
        context = _synthetic_context(target)
        inputs = build_standard_inputs(
            scenario=scenario,
            options=opts,
            provider=provider,
            model=model,
            model_version=model_version,
            static_profile=context,
            sct_state=context,
            permitted_history="",
            token_budget=token_budget,
            temperature=temperature,
            reasoning=reasoning,
            frozen_at=3000.0,
        )
        envelope_hashes.append(inputs["sct"].envelope_sha256)
        request = render_request(
            scenario=scenario,
            options=opts,
            frozen_input=inputs["sct"],
        )
        try:
            response = runner.predict(request, arm="sct")
            probabilities, predicted, confidence = validate_probability_response(opts, response)
        except Exception as exc:
            failures.append({
                "ordinal": str(ordinal),
                "target": target,
                "failure_class": type(exc).__name__,
            })
            break
        results.append({
            "ordinal": ordinal,
            "target": target,
            "predicted_choice": predicted,
            "confidence": confidence,
            "option_probabilities": probabilities,
            "target_matched_unique_argmax": predicted == target,
        })

    same_envelope = len(set(envelope_hashes)) <= 1
    passed = (
        len(results) == 2
        and not failures
        and same_envelope
        and all(row["target_matched_unique_argmax"] for row in results)
        and results[0]["predicted_choice"] != results[1]["predicted_choice"]
    )
    return {
        "schema": R12_CONTEXT_SCHEMA,
        "plan_sha256": plan_sha256,
        "provider": provider,
        "model": model,
        "model_version": model_version,
        "options": opts,
        "targets": targets,
        "results": results,
        "failures": failures,
        "attempted_calls": len(results) + len(failures),
        "same_model_settings_and_envelope": same_envelope,
        "automatic_retry": False,
        "replacement_cases": 0,
        "minimum_probability_gap_required": False,
        "satisfies_context_responsiveness_gate": passed,
        "valid_live_cases_added": 0,
        "execution_authority": "NONE",
    }


def run_r12_stable_single_model_void_dryrun(
    *,
    runner,
    cases: int,
    provider: str,
    model: str,
    model_version: str,
    runner_command_sha256: str | None = None,
) -> dict[str, Any]:
    """Run the stable single-model R12 VOID component without changing legacy R9-R11 evidence."""
    result = run_real_model_void_dryrun(
        runner=runner,
        cases=cases,
        provider=provider,
        model=model,
        model_version=model_version,
        runner_command_sha256=runner_command_sha256,
    )
    legacy_transport_pass = bool(result.get("satisfies_real_model_gate"))
    result.update({
        "schema": R12_VOID_SCHEMA,
        "r12_component": "STABLE_SINGLE_MODEL_VOID",
        "single_exact_model_for_all_cases": True,
        "automatic_retry": False,
        "replacement_cases": 0,
        "phase1_transport_component_pass": legacy_transport_pass,
        "satisfies_real_model_gate": False,
        "satisfies_r12_real_model_gate": False,
        "note_r12": (
            "Component receipt only. R12 requires this receipt plus the context-responsiveness "
            "sentinel and genuine operator/provider attestation before the scientific pre-Case gate can pass."
        ),
    })
    return result


def _is_sha256(value: str | None) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def qualify_r12_pre_case_gate(
    void_receipt: Mapping[str, Any],
    context_receipt: Mapping[str, Any],
    *,
    operator_attestation_sha256: str | None,
    operator_attestation_verified: bool = False,
) -> dict[str, Any]:
    """Deterministically adjudicate R12 evidence without granting enrollment authority."""
    blockers: list[str] = []

    if void_receipt.get("schema") != R12_VOID_SCHEMA:
        blockers.append("R12_STABLE_SINGLE_MODEL_VOID_RECEIPT_REQUIRED")
    if context_receipt.get("schema") != R12_CONTEXT_SCHEMA:
        blockers.append("R12_CONTEXT_RESPONSIVENESS_RECEIPT_REQUIRED")

    try:
        cases = int(void_receipt.get("cases", -1))
        vectors = int(void_receipt.get("prediction_vectors", -1))
        void_cases = int(void_receipt.get("void_cases", -1))
        valid_cases = int(void_receipt.get("valid_cases", -1))
        valid_after = int(void_receipt.get("valid_cases_after_void_exclusion", -1))
    except (TypeError, ValueError):
        cases = vectors = void_cases = valid_cases = valid_after = -1

    if not 10 <= cases <= 20:
        blockers.append("R12_VOID_CASE_COUNT_OUTSIDE_10_20")
    if vectors != cases * 3:
        blockers.append("R12_VOID_INCOMPLETE_ABC_PREDICTIONS")
    if void_cases != cases:
        blockers.append("R12_ALL_CASES_MUST_BE_VOID")
    if valid_cases != 0 or valid_after != 0:
        blockers.append("R12_VALID_LIVE_N_MUST_REMAIN_ZERO")
    if not bool(void_receipt.get("schema_transport_pass")):
        blockers.append("R12_SCHEMA_TRANSPORT_COMPONENT_FAILED")
    if not bool(void_receipt.get("store_verify_ok")):
        blockers.append("R12_STORE_VERIFY_FAILED")
    if void_receipt.get("automatic_retry") is not False:
        blockers.append("R12_AUTOMATIC_RETRY_FORBIDDEN")
    if int(void_receipt.get("replacement_cases", -1)) != 0:
        blockers.append("R12_REPLACEMENT_CASES_FORBIDDEN")
    if not bool(void_receipt.get("single_exact_model_for_all_cases")):
        blockers.append("R12_SINGLE_EXACT_MODEL_REQUIRED")
    if not bool(context_receipt.get("satisfies_context_responsiveness_gate")):
        blockers.append("R12_CONTEXT_RESPONSIVENESS_FAILED")
    if context_receipt.get("automatic_retry") is not False:
        blockers.append("R12_CONTEXT_AUTOMATIC_RETRY_FORBIDDEN")
    if context_receipt.get("minimum_probability_gap_required") is not False:
        blockers.append("R12_POSTHOC_PROBABILITY_GAP_THRESHOLD_FORBIDDEN")

    for field in ("provider", "model", "model_version"):
        if void_receipt.get(field) != context_receipt.get(field):
            blockers.append(f"R12_{field.upper()}_MISMATCH")

    if not _is_sha256(operator_attestation_sha256):
        blockers.append("R12_GENUINE_OPERATOR_ATTESTATION_REQUIRED")
    if operator_attestation_verified is not True:
        blockers.append("R12_OPERATOR_ATTESTATION_PROVENANCE_NOT_VERIFIED")

    scientific_pass = not blockers
    return {
        "schema": R12_QUALIFICATION_SCHEMA,
        "scientific_pre_case_gate_pass": scientific_pass,
        "blockers": blockers,
        "provider": void_receipt.get("provider"),
        "model": void_receipt.get("model"),
        "model_version": void_receipt.get("model_version"),
        "void_receipt_sha256": sha256_obj(dict(void_receipt)),
        "context_receipt_sha256": sha256_obj(dict(context_receipt)),
        "operator_attestation_sha256": operator_attestation_sha256 if _is_sha256(operator_attestation_sha256) else None,
        "operator_attestation_verified": operator_attestation_verified is True,
        "probability_policy": {
            "full_vectors_required": True,
            "minimum_probability_gap_required": False,
            "minimum_entropy_or_confidence_threshold_required": False,
            "context_responsiveness_required": True,
        },
        "case_001_authorized": False,
        "requires_fresh_valid_live_n_zero_before_enrollment": True,
        "requires_separate_owner_authorization": True,
        "execution_authority": "NONE",
        "note": (
            "A scientific PASS does not itself enroll Case #001, merge, deploy, spend money, "
            "or grant execution authority."
        ),
    }


def record_r12_qualification_pass(store, qualification: Mapping[str, Any]) -> dict[str, Any]:
    """Persist a scientific R12 PASS while keeping enrollment and execution closed."""
    if qualification.get("schema") != R12_QUALIFICATION_SCHEMA:
        raise EvidenceError("R12 qualification schema mismatch")
    if qualification.get("scientific_pre_case_gate_pass") is not True:
        raise EvidenceError("R12 scientific gate has not passed")
    if qualification.get("case_001_authorized") is not False:
        raise EvidenceError("R12 qualification must not self-authorize Case #001")
    if qualification.get("execution_authority") != "NONE":
        raise EvidenceError("R12 qualification cannot grant execution authority")
    if not list(store.query(kind="PRECASE_PROTOCOL_AMENDED")):
        raise EvidenceError("R12 protocol amendment must be recorded before qualification")
    if list(store.query(kind="CASE_FROZEN")):
        raise EvidenceError("R12 qualification must be recorded before any LIVE case")
    verify = store.verify()
    if not verify.ok:
        raise EvidenceError("Evidence Store verification failed before R12 qualification")

    qualification_sha256 = sha256_obj(dict(qualification))
    existing = list(store.query(kind=R12_QUALIFIED_EVENT))
    if existing:
        current = existing[-1].payload
        if current.get("qualification_sha256") != qualification_sha256:
            raise EvidenceError("different R12 qualification PASS already recorded")
        return dict(current)

    payload = {
        "qualification_sha256": qualification_sha256,
        "provider": qualification.get("provider"),
        "model": qualification.get("model"),
        "model_version": qualification.get("model_version"),
        "void_receipt_sha256": qualification.get("void_receipt_sha256"),
        "context_receipt_sha256": qualification.get("context_receipt_sha256"),
        "operator_attestation_sha256": qualification.get("operator_attestation_sha256"),
        "operator_attestation_verified": True,
        "case_001_authorized": False,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    store.append(R12_QUALIFIED_EVENT, payload)
    return payload


def r12_enrollment_gate_status(store) -> dict[str, Any]:
    """Return deterministic admission state. Scientific PASS is necessary but not sufficient."""
    qualifications = list(store.query(kind=R12_QUALIFIED_EVENT))
    authorizations = list(store.query(kind=R12_ENROLLMENT_AUTH_EVENT))
    qualification = qualifications[-1].payload if qualifications else None
    authorization = authorizations[-1].payload if authorizations else None
    qualification_sha256 = qualification.get("qualification_sha256") if qualification else None
    bound = bool(
        qualification
        and authorization
        and authorization.get("qualification_sha256") == qualification_sha256
        and authorization.get("execution_authority") == "NONE"
        and authorization.get("can_execute") is False
    )
    verify = store.verify()
    return {
        "scientific_pass_recorded": qualification is not None,
        "qualification_sha256": qualification_sha256,
        "owner_enrollment_authorization_recorded": authorization is not None,
        "authorization_bound_to_qualification": bound,
        "store_verify_ok": verify.ok,
        "live_enrollment_allowed": bool(bound and verify.ok),
        "execution_authority": "NONE",
    }


def authorize_case001_enrollment(store, *, approval_token: str) -> dict[str, Any]:
    """Record explicit owner enrollment approval; this is not execution authority."""
    status = r12_enrollment_gate_status(store)
    qualification_sha256 = status.get("qualification_sha256")
    if not status.get("scientific_pass_recorded") or not _is_sha256(qualification_sha256):
        raise EvidenceError("R12 scientific PASS must be recorded before owner enrollment approval")
    if list(store.query(kind="CASE_FROZEN")):
        raise EvidenceError("Case #001 owner approval must be recorded before any LIVE case")
    expected = f"APPROVE_SCT_CASE001:{qualification_sha256}"
    if approval_token != expected:
        raise EvidenceError("exact owner Case #001 approval token required")

    existing = list(store.query(kind=R12_ENROLLMENT_AUTH_EVENT))
    if existing:
        current = existing[-1].payload
        if current.get("qualification_sha256") != qualification_sha256:
            raise EvidenceError("owner approval is bound to a different R12 qualification")
        return dict(current)

    payload = {
        "qualification_sha256": qualification_sha256,
        "approval_token_sha256": sha256_obj(approval_token),
        "scope": "SCT_LIVE_EPOCH_001_ENROLLMENT",
        "case_001_authorized": True,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    store.append(R12_ENROLLMENT_AUTH_EVENT, payload)
    return payload


def require_r12_enrollment_authorized(store) -> dict[str, Any]:
    status = r12_enrollment_gate_status(store)
    if not status["live_enrollment_allowed"]:
        raise EvidenceError(
            "R12_PRECASE_ADMISSION_BLOCKED: scientific PASS plus exact owner Case #001 approval are required"
        )
    return status
