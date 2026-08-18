from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Any, Mapping, Sequence

from .canon import canonical_json, sha256_obj
from .errors import BenchError, EvidenceError

R13_PROTOCOL_SCHEMA = "sct.r13-precase-qualification/v1"
R13_MODEL_SELECTION_SCHEMA = "sct.epoch001-model-selection-manifest/v1"
R13_BASELINE_SCHEMA = "sct.epoch001-arm-b-baseline/v1"
R13_LOGIT_REQUEST_SCHEMA = "sct.r13-logit-request/v1"
R13_SENTINEL_SCHEMA = "sct.r13-balanced-context-sentinel/v1"
R13_PREFLIGHT_SCHEMA = "sct.r13-determinism-preflight/v1"
R13_VOID_SCHEMA = "sct.r13-stable-void/v1"
R13_QUALIFICATION_SCHEMA = "sct.r13-qualification/v1"
R13_PROTOCOL_EVENT = "R13_PRECASE_PROTOCOL_AMENDED"
R13_MODEL_EVENT = "R13_MODEL_SELECTION_SEALED"
R13_BASELINE_EVENT = "R13_BASELINE_SPEC_SEALED"
R13_QUALIFIED_EVENT = "R13_QUALIFICATION_PASSED"
R13_ENROLLMENT_AUTH_EVENT = "CASE001_ENROLLMENT_AUTHORIZED"
R13_FAILURE_EVENT = "R13_QUALIFICATION_FAILED"

R12_SOURCE_SHA = "61929ee088cd83f61b4bc3df97559da2f58bc6c9"
R12_TREE_SHA = "143f6da481909bb83167f12c102d5be10e4faba3"
R12_ARTIFACT_SHA256 = "a67404f2a3fd0778d86e2ec2fe6ca6f677a8e2056eaf1d38fb7f64825dd6d8c2"
R12_EVIDENCE_DB_SHA256 = "9223b6e78c76918c8f33ffe02cbbf2ddaad6212330661747908117017850be61"
R11_RECEIPT_SHA256 = "1c5937da898e89e92d9c9a1f905cb29b8e0aec133fb4fb3dffcfe74a94f1fd0c"

R13_ADAPTER_ID = "sct.r13-direct-constrained-label-logits/v2"
R13_CHOICE_PREFIX = "Selected option: "
R13_ALIAS_INVENTORY = tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
R13_VOID_CARDINALITIES = (2, 3, 4, 5, 6, 7, 8, 10, 12, 15)
R13_CONFIRMATORY_PRIMARY = "brier_skill_delta_c_minus_b"
R13_DESCRIPTIVE_SECONDARY = ("accuracy_delta_c_minus_b", "log_loss_delta_c_minus_b")
R13_SIGN_FLIP_INTERPRETATION = "SIGN_FLIP_SENSITIVITY_UNDER_SYMMETRY_NOT_RANDOM_ASSIGNMENT_INFERENCE"

R13_SYSTEM_PROMPT = (
    "You are a shadow-only prediction contestant. Predict which labeled option the principal will actually choose. "
    "Use only the scenario, labeled options, and personal_context. Do not invent personal facts. "
    "The scientific forecast is the constrained next-token distribution over the allowed option labels. "
    "Do not act, execute, re-query, or infer authority from this request."
)


@dataclass(frozen=True)
class AliasToken:
    alias: str
    token_id: int


@dataclass(frozen=True)
class CaseMapping:
    semantic_to_alias: Mapping[str, str]
    textual_order: tuple[str, ...]
    mapping_sha256: str


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def r13_protocol_manifest(*, r2_diagnostic_sha256: str) -> dict[str, Any]:
    if not _is_sha256(r2_diagnostic_sha256):
        raise ValueError("r2_diagnostic_sha256 must be 64 hex characters")
    body = {
        "schema": R13_PROTOCOL_SCHEMA,
        "status": "PROSPECTIVE_NOT_EXECUTED",
        "parent": {
            "r12_source_sha": R12_SOURCE_SHA,
            "r12_tree_sha": R12_TREE_SHA,
            "r12_artifact_sha256": R12_ARTIFACT_SHA256,
            "r12_evidence_db_sha256": R12_EVIDENCE_DB_SHA256,
            "r11_receipt_sha256": R11_RECEIPT_SHA256,
            "r2_diagnostic_sha256": r2_diagnostic_sha256.lower(),
        },
        "adapter": {
            "id": R13_ADAPTER_ID,
            "temperature": 1.0,
            "uniform_mix": 0.0,
            "rationale_before_choice": False,
            "fallback_distribution": None,
            "choice_prefix": R13_CHOICE_PREFIX,
        },
        "sentinel": {
            "schema": R13_SENTINEL_SCHEMA,
            "scenarios": 2,
            "mapping_order_variants_per_scenario": 3,
            "directed_contexts_per_variant": 3,
            "planned_calls": 18,
            "minimum_gap": None,
            "entropy_threshold": None,
            "confidence_threshold": None,
            "p_value": None,
        },
        "determinism_preflight_calls": 2,
        "stable_void": {
            "cases": 10,
            "cardinalities": R13_VOID_CARDINALITIES,
            "arms_per_case": 3,
            "planned_calls": 30,
        },
        "analysis_protocol": {
            "confirmatory_primary": R13_CONFIRMATORY_PRIMARY,
            "descriptive_secondary": R13_DESCRIPTIVE_SECONDARY,
            "n_ge_100_k_ge_6_semantics": "MINIMUM_INFERENCE_ADMISSION_FLOOR_NOT_POWER_OR_INDEPENDENCE_PROOF",
            "sign_flip_interpretation": R13_SIGN_FLIP_INTERPRETATION,
        },
        "automatic_retry": False,
        "replacement_cases": 0,
        "replacement_models": 0,
        "max_planned_real_model_calls_successful_run": 50,
        "valid_live_n": 0,
        "case_001_authorized": False,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    return {**body, "manifest_sha256": sha256_obj(body)}


def ensure_r13_protocol_amended(store, manifest: Mapping[str, Any]) -> dict[str, Any]:
    if manifest.get("schema") != R13_PROTOCOL_SCHEMA:
        raise EvidenceError("R13 protocol schema mismatch")
    if manifest.get("valid_live_n") != 0:
        raise EvidenceError("R13 protocol requires valid LIVE n = 0")
    if manifest.get("execution_authority") != "NONE" or manifest.get("can_execute") is not False:
        raise EvidenceError("R13 protocol cannot grant execution authority")
    if list(store.query(kind="CASE_FROZEN")):
        raise EvidenceError("R13 protocol must be recorded before any LIVE case")
    existing = list(store.query(kind=R13_PROTOCOL_EVENT))
    if existing:
        current = existing[-1].payload
        if current.get("manifest_sha256") != manifest.get("manifest_sha256"):
            raise EvidenceError("different R13 protocol already recorded")
        return dict(current)
    payload = {
        "manifest_sha256": manifest["manifest_sha256"],
        "r12_source_sha": R12_SOURCE_SHA,
        "r12_tree_sha": R12_TREE_SHA,
        "r12_artifact_sha256": R12_ARTIFACT_SHA256,
        "r12_evidence_db_sha256": R12_EVIDENCE_DB_SHA256,
        "r2_diagnostic_sha256": manifest["parent"]["r2_diagnostic_sha256"],
        "valid_live_n": 0,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    store.append(R13_PROTOCOL_EVENT, payload)
    return payload


def _require_text(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"R13 model manifest requires {key}")
    return value.strip()


def _alias_tokens_from_manifest(manifest: Mapping[str, Any]) -> tuple[AliasToken, ...]:
    raw = manifest.get("alias_tokens")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise EvidenceError("R13 model manifest requires alias_tokens")
    out: list[AliasToken] = []
    seen_alias: set[str] = set()
    seen_token: set[int] = set()
    for row in raw:
        if not isinstance(row, Mapping):
            raise EvidenceError("alias_tokens entries must be objects")
        alias = str(row.get("alias", ""))
        token_id = row.get("token_id")
        if alias not in R13_ALIAS_INVENTORY:
            raise EvidenceError("alias outside frozen inventory")
        if isinstance(token_id, bool) or not isinstance(token_id, int) or token_id < 0:
            raise EvidenceError("alias token_id must be a non-negative integer")
        if alias in seen_alias or token_id in seen_token:
            raise EvidenceError("alias/token IDs must be unique")
        seen_alias.add(alias)
        seen_token.add(token_id)
        out.append(AliasToken(alias=alias, token_id=token_id))
    order = {alias: i for i, alias in enumerate(R13_ALIAS_INVENTORY)}
    if [order[x.alias] for x in out] != sorted(order[x.alias] for x in out):
        raise EvidenceError("alias_tokens must follow frozen inventory order")
    return tuple(out)


def validate_model_selection_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if manifest.get("schema") != R13_MODEL_SELECTION_SCHEMA:
        raise EvidenceError("R13 model selection schema mismatch")
    for key in (
        "model_repo_or_provider_id", "model_revision", "runtime_backend", "runtime_version",
        "precision_or_quantization", "device_class", "context_window", "selection_rationale_non_r13",
    ):
        _require_text(manifest, key)
    if manifest.get("selection_must_not_use_r13_outputs") is not True:
        raise EvidenceError("model selection must be exogenous to R13 outputs")
    if manifest.get("exact_epoch001_live_substrate") is not True:
        raise EvidenceError("R13 must qualify the exact Epoch-001 LIVE substrate")
    if manifest.get("execution_authority") != "NONE":
        raise EvidenceError("model selection cannot grant execution authority")
    aliases = _alias_tokens_from_manifest(manifest)
    max_k = manifest.get("max_option_cardinality_required")
    if max_k != 15 or len(aliases) < max_k:
        raise EvidenceError("R13 requires at least 15 eligible frozen aliases")
    token_hashes = manifest.get("tokenizer_hashes")
    weight_hashes = manifest.get("weight_hashes")
    if not token_hashes or not weight_hashes:
        raise EvidenceError("model/tokenizer hashes are required")
    body = dict(manifest)
    body.pop("manifest_sha256", None)
    expected = sha256_obj(body)
    supplied = manifest.get("manifest_sha256")
    if supplied is not None and supplied != expected:
        raise EvidenceError("model selection manifest hash mismatch")
    return {**body, "manifest_sha256": expected}


def seal_model_selection(store, manifest: Mapping[str, Any], *, protocol_manifest_sha256: str) -> dict[str, Any]:
    validated = validate_model_selection_manifest(manifest)
    protocols = list(store.query(kind=R13_PROTOCOL_EVENT))
    if not protocols or protocols[-1].payload.get("manifest_sha256") != protocol_manifest_sha256:
        raise EvidenceError("matching R13 protocol must be recorded before model selection")
    if list(store.query(kind="CASE_FROZEN")):
        raise EvidenceError("model selection must be sealed before any LIVE case")
    existing = list(store.query(kind=R13_MODEL_EVENT))
    if existing:
        current = existing[-1].payload
        if current.get("model_selection_manifest_sha256") != validated["manifest_sha256"]:
            raise EvidenceError("different R13 model selection already sealed")
        return dict(current)
    payload = {
        "protocol_manifest_sha256": protocol_manifest_sha256,
        "model_selection_manifest_sha256": validated["manifest_sha256"],
        "model_repo_or_provider_id": validated["model_repo_or_provider_id"],
        "model_revision": validated["model_revision"],
        "execution_authority": "NONE",
        "can_execute": False,
    }
    store.append(R13_MODEL_EVENT, payload)
    return payload


def validate_baseline_spec(spec: Mapping[str, Any]) -> dict[str, Any]:
    if spec.get("schema") != R13_BASELINE_SCHEMA:
        raise EvidenceError("Arm B baseline schema mismatch")
    for key in (
        "profile_construction_policy", "retrieval_policy", "source_cutoff_policy",
        "admissible_evidence_pool", "context_selection_policy",
    ):
        _require_text(spec, key)
    if spec.get("disallow_sct_structured_claims") is not True:
        raise EvidenceError("Arm B must not consume SCT-only structured claims")
    ratio = spec.get("payload_parity_ratio")
    if isinstance(ratio, bool) or not isinstance(ratio, (int, float)) or float(ratio) != 1.15:
        raise EvidenceError("Arm B payload parity ratio must remain 1.15")
    if spec.get("execution_authority") != "NONE":
        raise EvidenceError("baseline spec cannot grant execution authority")
    body = dict(spec)
    body.pop("manifest_sha256", None)
    expected = sha256_obj(body)
    supplied = spec.get("manifest_sha256")
    if supplied is not None and supplied != expected:
        raise EvidenceError("Arm B baseline manifest hash mismatch")
    return {**body, "manifest_sha256": expected}


def seal_baseline_spec(store, spec: Mapping[str, Any], *, protocol_manifest_sha256: str) -> dict[str, Any]:
    from .r13_manifest_guard import validate_baseline_for_seal
    validated = validate_baseline_for_seal(spec)
    protocols = list(store.query(kind=R13_PROTOCOL_EVENT))
    if not protocols or protocols[-1].payload.get("manifest_sha256") != protocol_manifest_sha256:
        raise EvidenceError("matching R13 protocol must be recorded before baseline seal")
    existing = list(store.query(kind=R13_BASELINE_EVENT))
    if existing:
        current = existing[-1].payload
        if current.get("baseline_manifest_sha256") != validated["manifest_sha256"]:
            raise EvidenceError("different Arm B baseline already sealed")
        return dict(current)
    payload = {
        "protocol_manifest_sha256": protocol_manifest_sha256,
        "baseline_manifest_sha256": validated["manifest_sha256"],
        "disallow_sct_structured_claims": True,
        "payload_parity_ratio": 1.15,
        "execution_authority": "NONE",
        "can_execute": False,
    }
    store.append(R13_BASELINE_EVENT, payload)
    return payload


def first_aliases(manifest: Mapping[str, Any], k: int) -> tuple[AliasToken, ...]:
    aliases = _alias_tokens_from_manifest(manifest)
    if isinstance(k, bool) or not isinstance(k, int) or k < 2 or k > len(aliases):
        raise BenchError("R13 option cardinality outside sealed alias support")
    return aliases[:k]


def _stable_permutation(values: Sequence[str], seed_material: str, domain: str) -> tuple[str, ...]:
    keyed = []
    for idx, value in enumerate(values):
        digest = hashlib.sha256(f"{domain}\0{seed_material}\0{idx}\0{value}".encode("utf-8")).hexdigest()
        keyed.append((digest, idx, value))
    return tuple(row[2] for row in sorted(keyed))


def derive_case_mapping(
    *, case_id: str, semantic_options: Sequence[str], alias_manifest: Mapping[str, Any], epoch_manifest_sha256: str
) -> CaseMapping:
    options = tuple(dict.fromkeys(str(x).strip() for x in semantic_options if str(x).strip()))
    if len(options) < 2:
        raise BenchError("at least two distinct semantic options required")
    if not _is_sha256(epoch_manifest_sha256):
        raise BenchError("epoch manifest SHA-256 required")
    aliases = tuple(x.alias for x in first_aliases(alias_manifest, len(options)))
    seed = f"SCT_R13_CASE_MAPPING_V1\0{case_id}\0{epoch_manifest_sha256}"
    alias_order = _stable_permutation(aliases, seed, "alias")
    text_order = _stable_permutation(options, seed, "text")
    mapping = {option: alias_order[i] for i, option in enumerate(options)}
    body = {"case_id": case_id, "semantic_to_alias": mapping, "textual_order": text_order, "epoch_manifest_sha256": epoch_manifest_sha256}
    return CaseMapping(mapping, text_order, sha256_obj(body))


def freeze_case_mapping(
    store, *, case_id: str, semantic_options: Sequence[str], alias_manifest: Mapping[str, Any],
    protocol_manifest_sha256: str, model_selection_manifest_sha256: str,
) -> dict[str, Any]:
    if any(e.kind == "PREDICTION_COMMITTED" for e in store.query() if e.payload.get("case_id") == case_id):
        raise EvidenceError("R13 mapping must be frozen before any prediction")
    mapping = derive_case_mapping(
        case_id=case_id,
        semantic_options=semantic_options,
        alias_manifest=alias_manifest,
        epoch_manifest_sha256=protocol_manifest_sha256,
    )
    payload = {
        "case_id": case_id,
        "protocol_manifest_sha256": protocol_manifest_sha256,
        "model_selection_manifest_sha256": model_selection_manifest_sha256,
        "semantic_to_alias": dict(mapping.semantic_to_alias),
        "textual_order": mapping.textual_order,
        "mapping_sha256": mapping.mapping_sha256,
        "execution_authority": "NONE",
    }
    existing = [e for e in store.query(kind="R13_CASE_MAPPING_FROZEN") if e.payload.get("case_id") == case_id]
    if existing:
        if existing[-1].payload.get("mapping_sha256") != mapping.mapping_sha256:
            raise EvidenceError("different R13 mapping already frozen for case")
        return dict(existing[-1].payload)
    store.append("R13_CASE_MAPPING_FROZEN", payload)
    return payload


def _request_payload_from_standard(request: Mapping[str, Any]) -> tuple[str, tuple[str, ...], str]:
    messages = request.get("messages")
    if not isinstance(messages, Sequence) or len(messages) < 2:
        raise BenchError("standard request messages missing")
    try:
        payload = json.loads(str(messages[-1]["content"]))
    except Exception as exc:
        raise BenchError("standard request user payload invalid") from exc
    scenario = str(payload.get("scenario", "")).strip()
    options = tuple(str(x).strip() for x in payload.get("options", ()) if str(x).strip())
    context = str(payload.get("personal_context", ""))
    if not scenario or len(options) < 2 or not context:
        raise BenchError("standard request payload incomplete")
    return scenario, options, context


def render_r13_logit_request(
    *, scenario: str, semantic_options: Sequence[str], personal_context: str, semantic_to_alias: Mapping[str, str],
    textual_order: Sequence[str], provider: str, model: str, model_version: str,
) -> dict[str, Any]:
    options = tuple(semantic_options)
    if set(options) != set(semantic_to_alias) or set(options) != set(textual_order):
        raise BenchError("R13 mapping/order must cover exact semantic options")
    labeled = [{"label": semantic_to_alias[opt], "semantic_option": opt} for opt in textual_order]
    user = canonical_json({
        "scenario": scenario,
        "labeled_options": labeled,
        "personal_context": personal_context,
        "constraints": {"shadow_only": True, "do_not_execute": True, "do_not_requery_for_a_better_answer": True},
    })
    envelope = {
        "system_prompt": R13_SYSTEM_PROMPT,
        "scenario": scenario,
        "semantic_options": options,
        "semantic_to_alias": dict(semantic_to_alias),
        "textual_order": tuple(textual_order),
        "provider": provider,
        "model": model,
        "model_version": model_version,
        "choice_prefix": R13_CHOICE_PREFIX,
        "adapter_id": R13_ADAPTER_ID,
    }
    return {
        "schema": R13_LOGIT_REQUEST_SCHEMA,
        "provider": provider,
        "model": model,
        "model_version": model_version,
        "messages": [
            {"role": "system", "content": R13_SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": R13_CHOICE_PREFIX},
        ],
        "envelope_sha256": sha256_obj(envelope),
        "choice_prefix": R13_CHOICE_PREFIX,
        "execution_authority": "NONE",
        "can_execute": False,
    }


def constrained_probabilities(
    *, semantic_options: Sequence[str], semantic_to_alias: Mapping[str, str], alias_logits: Mapping[str, Any]
) -> dict[str, float]:
    options = tuple(semantic_options)
    aliases = tuple(semantic_to_alias[o] for o in options)
    if set(alias_logits) != set(aliases):
        raise BenchError("allowed-token logits must contain exact alias set")
    logits: list[float] = []
    for alias in aliases:
        value = alias_logits[alias]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise BenchError("allowed-token logits must be finite numeric values")
        logits.append(float(value))
    maximum = max(logits)
    exps = [math.exp(x - maximum) for x in logits]
    total = sum(exps)
    probs = [x / total for x in exps]
    out = {options[i]: probs[i] for i in range(len(options))}
    if not all(math.isfinite(v) and 0.0 < v < 1.0 for v in out.values()):
        raise BenchError("R13 constrained probabilities invalid")
    if abs(sum(out.values()) - 1.0) > 1e-12:
        raise BenchError("R13 constrained probabilities do not sum to one")
    return out


class R13CasePredictionRunner:
    """Adapter from a raw allowed-token-logit runner to the existing arena PredictionRunner contract."""

    def __init__(self, *, logit_runner, case_id: str, mapping: Mapping[str, str], textual_order: Sequence[str], model_manifest: Mapping[str, Any]):
        self.logit_runner = logit_runner
        self.case_id = case_id
        self.mapping = dict(mapping)
        self.textual_order = tuple(textual_order)
        self.model_manifest = validate_model_selection_manifest(model_manifest)

    def predict(self, request: Mapping[str, Any], *, arm: str) -> Mapping[str, Any]:
        scenario, options, context = _request_payload_from_standard(request)
        if set(options) != set(self.mapping) or set(options) != set(self.textual_order):
            raise BenchError("frozen R13 case mapping does not match request options")
        aliases = tuple(self.mapping[o] for o in options)
        token_rows = {x.alias: x.token_id for x in first_aliases(self.model_manifest, len(options))}
        if not set(aliases).issubset(token_rows):
            raise BenchError("frozen R13 aliases not supported by model manifest")
        r13_request = render_r13_logit_request(
            scenario=scenario,
            semantic_options=options,
            personal_context=context,
            semantic_to_alias=self.mapping,
            textual_order=self.textual_order,
            provider=request["provider"],
            model=request["model"],
            model_version=request["model_version"],
        )
        raw = self.logit_runner.allowed_token_logits(r13_request, aliases=aliases)
        probs = constrained_probabilities(semantic_options=options, semantic_to_alias=self.mapping, alias_logits=raw)
        return {
            "option_probabilities": probs,
            "reasons": ["R13_DIRECT_CONSTRAINED_LABEL_LOGITS_FORECAST_COMMITTED_BEFORE_RATIONALE"],
            "change_conditions": [],
            "would_escalate": False,
        }


def _sentinel_scenarios() -> tuple[tuple[str, tuple[str, str, str]], ...]:
    return (
        ("Synthetic qualification only. Select one of three abstract plans for a fictional task.", ("PLAN_X", "PLAN_Y", "PLAN_Z")),
        ("Synthetic qualification only. Select one of three abstract configurations for a fictional device.", ("CONFIG_R", "CONFIG_S", "CONFIG_T")),
    )


def _latin_mappings(options: Sequence[str], aliases: Sequence[str]) -> tuple[tuple[dict[str, str], tuple[str, ...]], ...]:
    x, y, z = options
    a, b, c = aliases
    return (
        ({x: a, y: b, z: c}, (x, y, z)),
        ({x: b, y: c, z: a}, (y, z, x)),
        ({x: c, y: a, z: b}, (z, x, y)),
    )


def _directed_context(target: str) -> str:
    return (
        "SYNTHETIC QUALIFICATION ONLY. The principal has an explicit stable preference to choose "
        f"{target} among the listed options. Use this fact only for this VOID qualification call."
    )


def _model_identity(manifest: Mapping[str, Any]) -> tuple[str, str]:
    validated = validate_model_selection_manifest(manifest)
    return validated["model_repo_or_provider_id"], validated["model_revision"]


def run_r13_determinism_preflight(*, logit_runner, model_manifest: Mapping[str, Any], protocol_manifest_sha256: str) -> dict[str, Any]:
    aliases = tuple(x.alias for x in first_aliases(model_manifest, 3))
    provider_model, version = _model_identity(model_manifest)
    options = ("NEUTRAL_X", "NEUTRAL_Y", "NEUTRAL_Z")
    mapping = {options[i]: aliases[i] for i in range(3)}
    request = render_r13_logit_request(
        scenario="Synthetic deterministic runtime preflight.",
        semantic_options=options,
        personal_context="SYNTHETIC QUALIFICATION ONLY. No preference is specified.",
        semantic_to_alias=mapping,
        textual_order=options,
        provider=provider_model,
        model=provider_model,
        model_version=version,
    )
    first = logit_runner.allowed_token_logits(request, aliases=aliases)
    second = logit_runner.allowed_token_logits(request, aliases=aliases)
    first_serialized = canonical_json({a: float(first[a]) for a in aliases})
    second_serialized = canonical_json({a: float(second[a]) for a in aliases})
    passed = first_serialized == second_serialized
    return {
        "schema": R13_PREFLIGHT_SCHEMA,
        "protocol_manifest_sha256": protocol_manifest_sha256,
        "model_selection_manifest_sha256": validate_model_selection_manifest(model_manifest)["manifest_sha256"],
        "planned_calls": 2,
        "attempted_calls": 2,
        "first_logits": {a: float(first[a]) for a in aliases},
        "second_logits": {a: float(second[a]) for a in aliases},
        "deterministic": passed,
        "automatic_retry": False,
        "replacement_models": 0,
        "valid_live_cases_added": 0,
        "execution_authority": "NONE",
    }


def run_r13_balanced_context_sentinel(*, logit_runner, model_manifest: Mapping[str, Any], protocol_manifest_sha256: str) -> dict[str, Any]:
    aliases = tuple(x.alias for x in first_aliases(model_manifest, 3))
    provider_model, version = _model_identity(model_manifest)
    calls: list[dict[str, Any]] = []
    groups: dict[tuple[int, int], dict[str, dict[str, float]]] = {}
    try:
        for s_idx, (scenario, options) in enumerate(_sentinel_scenarios(), start=1):
            for m_idx, (mapping, text_order) in enumerate(_latin_mappings(options, aliases), start=1):
                key = (s_idx, m_idx)
                groups[key] = {}
                for target in options:
                    request = render_r13_logit_request(
                        scenario=scenario,
                        semantic_options=options,
                        personal_context=_directed_context(target),
                        semantic_to_alias=mapping,
                        textual_order=text_order,
                        provider=provider_model,
                        model=provider_model,
                        model_version=version,
                    )
                    raw = logit_runner.allowed_token_logits(request, aliases=tuple(mapping[o] for o in options))
                    probs = constrained_probabilities(semantic_options=options, semantic_to_alias=mapping, alias_logits=raw)
                    groups[key][target] = probs
                    calls.append({
                        "scenario_id": f"S{s_idx}",
                        "mapping_id": f"M{m_idx}",
                        "target": target,
                        "semantic_to_alias": dict(mapping),
                        "textual_order": text_order,
                        "option_probabilities": probs,
                        "envelope_sha256": request["envelope_sha256"],
                    })
    except Exception as exc:
        return {
            "schema": R13_SENTINEL_SCHEMA,
            "protocol_manifest_sha256": protocol_manifest_sha256,
            "model_selection_manifest_sha256": validate_model_selection_manifest(model_manifest)["manifest_sha256"],
            "planned_calls": 18,
            "attempted_calls": len(calls) + 1,
            "calls": calls,
            "relations": [],
            "failure_class": type(exc).__name__,
            "satisfies_context_responsiveness_gate": False,
            "minimum_probability_gap_required": False,
            "entropy_threshold_required": False,
            "automatic_retry": False,
            "replacement_cases": 0,
            "valid_live_cases_added": 0,
            "execution_authority": "NONE",
        }
    relations: list[dict[str, Any]] = []
    for (s_idx, m_idx), by_target in groups.items():
        options = next(x[1] for i, x in enumerate(_sentinel_scenarios(), start=1) if i == s_idx)
        for target in options:
            own = by_target[target][target]
            others = {other: by_target[other][target] for other in options if other != target}
            relation_pass = all(own > value for value in others.values())
            relations.append({
                "scenario_id": f"S{s_idx}",
                "mapping_id": f"M{m_idx}",
                "target": target,
                "q_target_under_own_context": own,
                "q_target_under_other_contexts": others,
                "strict_directional_relation_pass": relation_pass,
            })
    passed = len(calls) == 18 and len(relations) == 18 and all(x["strict_directional_relation_pass"] for x in relations)
    return {
        "schema": R13_SENTINEL_SCHEMA,
        "protocol_manifest_sha256": protocol_manifest_sha256,
        "model_selection_manifest_sha256": validate_model_selection_manifest(model_manifest)["manifest_sha256"],
        "planned_calls": 18,
        "attempted_calls": len(calls),
        "calls": calls,
        "relations": relations,
        "satisfies_context_responsiveness_gate": passed,
        "minimum_probability_gap_required": False,
        "entropy_threshold_required": False,
        "confidence_threshold_required": False,
        "p_value_required": False,
        "automatic_retry": False,
        "replacement_cases": 0,
        "valid_live_cases_added": 0,
        "execution_authority": "NONE",
    }


def run_r13_stable_void(*, logit_runner, model_manifest: Mapping[str, Any], protocol_manifest_sha256: str) -> dict[str, Any]:
    validated = validate_model_selection_manifest(model_manifest)
    provider_model, version = _model_identity(validated)
    calls: list[dict[str, Any]] = []
    try:
        for index, k in enumerate(R13_VOID_CARDINALITIES, start=1):
            options = tuple(f"VOID_{index:02d}_OPT_{j:02d}" for j in range(1, k + 1))
            case_id = f"R13-VOID-{index:02d}-K{k}"
            mapping = derive_case_mapping(case_id=case_id, semantic_options=options, alias_manifest=validated, epoch_manifest_sha256=protocol_manifest_sha256)
            contexts = {
                "generic": "NONE",
                "profile_rag": f"SYNTHETIC_VOID_CONTEXT_{index:02d}",
                "sct": f"SYNTHETIC_VOID_CONTEXT_{index:02d}",
            }
            envelope_hashes = set()
            for arm in ("generic", "profile_rag", "sct"):
                request = render_r13_logit_request(
                    scenario=f"Synthetic stable transport VOID case {index}.",
                    semantic_options=options,
                    personal_context=contexts[arm],
                    semantic_to_alias=mapping.semantic_to_alias,
                    textual_order=mapping.textual_order,
                    provider=provider_model,
                    model=provider_model,
                    model_version=version,
                )
                envelope_hashes.add(request["envelope_sha256"])
                aliases = tuple(mapping.semantic_to_alias[o] for o in options)
                raw = logit_runner.allowed_token_logits(request, aliases=aliases)
                probs = constrained_probabilities(semantic_options=options, semantic_to_alias=mapping.semantic_to_alias, alias_logits=raw)
                calls.append({"case_id": case_id, "k": k, "arm": arm, "option_probabilities": probs, "mapping_sha256": mapping.mapping_sha256})
            if len(envelope_hashes) != 1:
                raise BenchError("R13 stable VOID envelope parity violation")
    except Exception as exc:
        return {
            "schema": R13_VOID_SCHEMA,
            "protocol_manifest_sha256": protocol_manifest_sha256,
            "model_selection_manifest_sha256": validated["manifest_sha256"],
            "planned_cases": 10,
            "planned_calls": 30,
            "attempted_calls": len(calls) + 1,
            "calls": calls,
            "failure_class": type(exc).__name__,
            "stable_void_pass": False,
            "automatic_retry": False,
            "replacement_cases": 0,
            "valid_live_cases_added": 0,
            "execution_authority": "NONE",
        }
    return {
        "schema": R13_VOID_SCHEMA,
        "protocol_manifest_sha256": protocol_manifest_sha256,
        "model_selection_manifest_sha256": validated["manifest_sha256"],
        "planned_cases": 10,
        "planned_calls": 30,
        "attempted_calls": len(calls),
        "calls": calls,
        "stable_void_pass": len(calls) == 30,
        "automatic_retry": False,
        "replacement_cases": 0,
        "valid_live_cases_added": 0,
        "execution_authority": "NONE",
    }


def qualify_r13_pre_case_gate(
    preflight: Mapping[str, Any], sentinel: Mapping[str, Any], stable_void: Mapping[str, Any], *,
    operator_attestation_sha256: str | None, operator_attestation_verified: bool,
) -> dict[str, Any]:
    blockers: list[str] = []
    if preflight.get("schema") != R13_PREFLIGHT_SCHEMA or preflight.get("deterministic") is not True:
        blockers.append("R13_RUNTIME_NONDETERMINISTIC_FAIL")
    if int(preflight.get("attempted_calls", -1)) != 2:
        blockers.append("R13_PREFLIGHT_CALL_COUNT_MISMATCH")
    if sentinel.get("schema") != R13_SENTINEL_SCHEMA or sentinel.get("satisfies_context_responsiveness_gate") is not True:
        blockers.append("R13_CONTEXT_SENTINEL_FAILED")
    if int(sentinel.get("attempted_calls", -1)) != 18 or len(sentinel.get("relations", ())) != 18:
        blockers.append("R13_SENTINEL_CALL_COUNT_MISMATCH")
    if stable_void.get("schema") != R13_VOID_SCHEMA or stable_void.get("stable_void_pass") is not True:
        blockers.append("R13_STABLE_VOID_FAILED")
    if int(stable_void.get("attempted_calls", -1)) != 30:
        blockers.append("R13_STABLE_VOID_CALL_COUNT_MISMATCH")
    for receipt in (preflight, sentinel, stable_void):
        if receipt.get("automatic_retry") is not False:
            blockers.append("R13_AUTOMATIC_RETRY_FORBIDDEN")
        if int(receipt.get("replacement_cases", 0)) != 0:
            blockers.append("R13_REPLACEMENT_CASES_FORBIDDEN")
        if int(receipt.get("valid_live_cases_added", -1)) != 0:
            blockers.append("R13_VALID_LIVE_N_MUST_REMAIN_ZERO")
        if receipt.get("execution_authority") != "NONE":
            blockers.append("R13_EXECUTION_AUTHORITY_FORBIDDEN")
    hashes = {receipt.get("protocol_manifest_sha256") for receipt in (preflight, sentinel, stable_void)}
    model_hashes = {receipt.get("model_selection_manifest_sha256") for receipt in (preflight, sentinel, stable_void)}
    if len(hashes) != 1 or not _is_sha256(next(iter(hashes), None)):
        blockers.append("R13_PROTOCOL_BINDING_MISMATCH")
    if len(model_hashes) != 1 or not _is_sha256(next(iter(model_hashes), None)):
        blockers.append("R13_MODEL_BINDING_MISMATCH")
    if not _is_sha256(operator_attestation_sha256):
        blockers.append("R13_OPERATOR_ATTESTATION_REQUIRED")
    if operator_attestation_verified is not True:
        blockers.append("R13_OPERATOR_ATTESTATION_PROVENANCE_NOT_VERIFIED")
    passed = not blockers
    return {
        "schema": R13_QUALIFICATION_SCHEMA,
        "scientific_pre_case_gate_pass": passed,
        "blockers": blockers,
        "protocol_manifest_sha256": next(iter(hashes), None) if len(hashes) == 1 else None,
        "model_selection_manifest_sha256": next(iter(model_hashes), None) if len(model_hashes) == 1 else None,
        "preflight_receipt_sha256": sha256_obj(dict(preflight)),
        "sentinel_receipt_sha256": sha256_obj(dict(sentinel)),
        "stable_void_receipt_sha256": sha256_obj(dict(stable_void)),
        "operator_attestation_sha256": operator_attestation_sha256 if _is_sha256(operator_attestation_sha256) else None,
        "operator_attestation_verified": operator_attestation_verified is True,
        "planned_real_model_calls": 50,
        "case_001_authorized": False,
        "can_execute": False,
        "execution_authority": "NONE",
    }


def record_r13_qualification_pass(store, qualification: Mapping[str, Any]) -> dict[str, Any]:
    if qualification.get("schema") != R13_QUALIFICATION_SCHEMA or qualification.get("scientific_pre_case_gate_pass") is not True:
        raise EvidenceError("R13 scientific gate has not passed")
    if qualification.get("case_001_authorized") is not False or qualification.get("execution_authority") != "NONE":
        raise EvidenceError("R13 qualification cannot self-authorize or execute")
    protocols = list(store.query(kind=R13_PROTOCOL_EVENT))
    models = list(store.query(kind=R13_MODEL_EVENT))
    baselines = list(store.query(kind=R13_BASELINE_EVENT))
    if not protocols or protocols[-1].payload.get("manifest_sha256") != qualification.get("protocol_manifest_sha256"):
        raise EvidenceError("R13 qualification protocol binding missing")
    if not models or models[-1].payload.get("model_selection_manifest_sha256") != qualification.get("model_selection_manifest_sha256"):
        raise EvidenceError("R13 qualification model binding missing")
    if not baselines or baselines[-1].payload.get("protocol_manifest_sha256") != qualification.get("protocol_manifest_sha256"):
        raise EvidenceError("Arm B baseline must be sealed before R13 qualification PASS")
    if list(store.query(kind="CASE_FROZEN")):
        raise EvidenceError("R13 qualification must precede any LIVE case")
    verify = store.verify()
    if not verify.ok:
        raise EvidenceError("Evidence Store verification failed before R13 qualification")
    qsha = sha256_obj(dict(qualification))
    existing = list(store.query(kind=R13_QUALIFIED_EVENT))
    if existing:
        if existing[-1].payload.get("qualification_sha256") != qsha:
            raise EvidenceError("different R13 qualification PASS already recorded")
        return dict(existing[-1].payload)
    payload = {
        "qualification_sha256": qsha,
        "protocol_manifest_sha256": qualification["protocol_manifest_sha256"],
        "model_selection_manifest_sha256": qualification["model_selection_manifest_sha256"],
        "baseline_manifest_sha256": baselines[-1].payload["baseline_manifest_sha256"],
        "preflight_receipt_sha256": qualification["preflight_receipt_sha256"],
        "sentinel_receipt_sha256": qualification["sentinel_receipt_sha256"],
        "stable_void_receipt_sha256": qualification["stable_void_receipt_sha256"],
        "operator_attestation_sha256": qualification["operator_attestation_sha256"],
        "case_001_authorized": False,
        "valid_live_n": 0,
        "can_execute": False,
        "execution_authority": "NONE",
    }
    store.append(R13_QUALIFIED_EVENT, payload)
    return payload


def r13_enrollment_gate_status(store) -> dict[str, Any]:
    qualifications = list(store.query(kind=R13_QUALIFIED_EVENT))
    authorizations = [e for e in store.query(kind=R13_ENROLLMENT_AUTH_EVENT) if e.payload.get("protocol") == "R13"]
    baselines = list(store.query(kind=R13_BASELINE_EVENT))
    qualification = qualifications[-1].payload if qualifications else None
    authorization = authorizations[-1].payload if authorizations else None
    qsha = qualification.get("qualification_sha256") if qualification else None
    bound = bool(qualification and authorization and authorization.get("qualification_sha256") == qsha)
    baseline_bound = bool(qualification and baselines and qualification.get("baseline_manifest_sha256") == baselines[-1].payload.get("baseline_manifest_sha256"))
    verify = store.verify()
    return {
        "scientific_pass_recorded": qualification is not None,
        "qualification_sha256": qsha,
        "baseline_spec_sealed": bool(baselines),
        "baseline_bound_to_qualification": baseline_bound,
        "owner_enrollment_authorization_recorded": authorization is not None,
        "authorization_bound_to_qualification": bound,
        "store_verify_ok": verify.ok,
        "live_enrollment_allowed": bool(bound and baseline_bound and verify.ok),
        "execution_authority": "NONE",
    }


def authorize_case001_r13(store, *, approval_token: str) -> dict[str, Any]:
    status = r13_enrollment_gate_status(store)
    qsha = status.get("qualification_sha256")
    if not status.get("scientific_pass_recorded") or not _is_sha256(qsha):
        raise EvidenceError("R13 scientific PASS required before Case #001 authorization")
    if not status.get("baseline_spec_sealed"):
        raise EvidenceError("Arm B baseline must be sealed before Case #001 authorization")
    if list(store.query(kind="CASE_FROZEN")):
        raise EvidenceError("Case #001 authorization must precede any LIVE case")
    expected = f"APPROVE_SCT_CASE001_R13:{qsha}"
    if approval_token != expected:
        raise EvidenceError("exact R13 owner Case #001 approval token required")
    existing = [e for e in store.query(kind=R13_ENROLLMENT_AUTH_EVENT) if e.payload.get("protocol") == "R13"]
    if existing:
        if existing[-1].payload.get("qualification_sha256") != qsha:
            raise EvidenceError("existing R13 authorization bound to different qualification")
        return dict(existing[-1].payload)
    payload = {
        "protocol": "R13",
        "qualification_sha256": qsha,
        "approval_token_sha256": sha256_obj(approval_token),
        "scope": "SCT_LIVE_EPOCH_001_ENROLLMENT",
        "case_001_authorized": True,
        "can_execute": False,
        "execution_authority": "NONE",
    }
    store.append(R13_ENROLLMENT_AUTH_EVENT, payload)
    return payload


def require_r13_enrollment_authorized(store) -> dict[str, Any]:
    status = r13_enrollment_gate_status(store)
    if not status["live_enrollment_allowed"]:
        raise EvidenceError("R13_PRECASE_ADMISSION_BLOCKED: scientific PASS, sealed Arm B baseline, and exact owner authorization required")
    return status
