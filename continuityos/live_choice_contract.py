"""LIVE-0.1 explicit choice-space contracts for prospective TwinBench cases.

The first real LIVE attempt exposed a case-design failure: two registered options were
not actually mutually exclusive. This module keeps SCT-R2's exact single-choice scoring
model, but compiles real-world concurrent or priority decisions into an explicit set of
mutually exclusive outcomes before any contestant prediction is committed.

It is shadow-only. It does not call models, execute actions, mutate canon, or grant
authority.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple, Union
import hashlib
import json

from .decision_twin import DecisionTwinError
from .live_twinbench import CaseEligibility, FrozenContestantInput, prepare_live_case
from .twinbench import TwinBenchArena

CHOICE_SCHEMA = "continuityos.sct.live-choice-contract/v1"
CHOICE_MODES = ("EXCLUSIVE", "COMBINABLE", "PRIORITY")
_RESERVED = {"NEITHER", "SPLIT"}


def _cj(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(value: Any) -> str:
    raw = value if isinstance(value, str) else _cj(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DecisionTwinError(f"{field} must be a non-empty string")
    return value.strip()


def _items(values: Sequence[str], field: str) -> Tuple[str, ...]:
    out = []
    for value in values:
        item = _text(value, field)
        if item not in out:
            out.append(item)
    if len(out) < 2:
        raise DecisionTwinError(f"{field} must contain at least two distinct values")
    return tuple(out)


@dataclass(frozen=True)
class ChoiceContract:
    mode: str
    actions: Tuple[str, ...]
    compiled_options: Tuple[str, ...]
    allow_none: bool
    allow_split: bool
    contract_sha256: str
    schema: str = CHOICE_SCHEMA
    mode_runtime: str = "SHADOW"
    execution_authority: str = "NONE"
    can_execute: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_choice_contract(
    actions: Sequence[str],
    *,
    mode: str,
    allow_none: bool = False,
    allow_split: bool = False,
) -> ChoiceContract:
    """Compile one real decision space into mutually exclusive scoreable outcomes.

    EXCLUSIVE: each supplied action/outcome is already mutually exclusive.
    COMBINABLE: all non-empty action subsets become explicit outcomes, e.g. A, B, A+B.
    PRIORITY: asks what happens first; outcomes become A_FIRST, B_FIRST, optionally SPLIT.
    """
    actions_t = _items(actions, "actions")
    mode = _text(mode, "mode").upper()
    if mode not in CHOICE_MODES:
        raise DecisionTwinError(f"mode must be one of {CHOICE_MODES}")
    if not isinstance(allow_none, bool) or not isinstance(allow_split, bool):
        raise DecisionTwinError("allow_none and allow_split must be booleans")
    if allow_split and mode != "PRIORITY":
        raise DecisionTwinError("allow_split is valid only for PRIORITY mode")

    for action in actions_t:
        if action in _RESERVED or "+" in action or action.endswith("_FIRST"):
            raise DecisionTwinError(
                "actions may not use reserved labels, '+', or the '_FIRST' suffix"
            )

    if mode == "EXCLUSIVE":
        options = list(actions_t)
    elif mode == "COMBINABLE":
        if len(actions_t) > 4:
            raise DecisionTwinError("COMBINABLE mode supports at most four actions")
        options = []
        for size in range(1, len(actions_t) + 1):
            for subset in combinations(actions_t, size):
                options.append("+".join(subset))
    else:  # PRIORITY
        options = [f"{action}_FIRST" for action in actions_t]
        if allow_split:
            options.append("SPLIT")

    if allow_none:
        options.append("NEITHER")

    identity = {
        "schema": CHOICE_SCHEMA,
        "mode": mode,
        "actions": actions_t,
        "compiled_options": tuple(options),
        "allow_none": allow_none,
        "allow_split": allow_split,
        "mode_runtime": "SHADOW",
        "execution_authority": "NONE",
        "can_execute": False,
    }
    return ChoiceContract(
        mode=mode,
        actions=actions_t,
        compiled_options=tuple(options),
        allow_none=allow_none,
        allow_split=allow_split,
        contract_sha256=_sha(identity),
    )


def normalize_human_choice(
    contract: ChoiceContract,
    choice: Union[str, Sequence[str]],
) -> str:
    """Normalize the human commitment to one registered scoreable outcome.

    For COMBINABLE mode, a sequence such as ("A", "B") becomes the registered "A+B"
    outcome in contract action order. Empty selection requires allow_none=True.
    Other modes require one exact registered string.
    """
    if not isinstance(contract, ChoiceContract):
        raise DecisionTwinError("contract must be a ChoiceContract")

    if contract.mode == "COMBINABLE" and not isinstance(choice, str):
        selected = []
        for value in choice:
            item = _text(value, "choice")
            if item not in contract.actions:
                raise DecisionTwinError(f"unregistered action in human choice: {item}")
            if item not in selected:
                selected.append(item)
        if not selected:
            normalized = "NEITHER"
        else:
            normalized = "+".join(action for action in contract.actions if action in selected)
    else:
        if not isinstance(choice, str):
            raise DecisionTwinError("human choice must be one exact registered string")
        normalized = _text(choice, "choice")

    if normalized not in contract.compiled_options:
        raise DecisionTwinError(
            f"human outcome is outside the pre-registered choice contract: {normalized}"
        )
    return normalized


def prepare_contracted_live_case(
    arena: TwinBenchArena,
    *,
    root: str | Path,
    case_id: str,
    decision_surface: str,
    situation: str,
    choice_contract: ChoiceContract,
    frozen_inputs: Mapping[str, FrozenContestantInput],
    eligibility: Optional[CaseEligibility] = None,
    opened_at: Optional[float] = None,
) -> Dict[str, Any]:
    """Prepare a LIVE-0 case whose choice space is explicit before prediction commit."""
    if not isinstance(choice_contract, ChoiceContract):
        raise DecisionTwinError("choice_contract is required for LIVE-0.1 cases")

    manifest = prepare_live_case(
        arena,
        root=root,
        case_id=case_id,
        decision_surface=decision_surface,
        situation=situation,
        options=choice_contract.compiled_options,
        frozen_inputs=frozen_inputs,
        eligibility=eligibility,
        opened_at=opened_at,
    )

    case_dir = Path(root) / case_id
    contract_path = case_dir / "choice_contract.json"
    contract_path.write_text(
        json.dumps(choice_contract.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    request_hashes: Dict[str, str] = {}
    for name in sorted(frozen_inputs):
        path = case_dir / "requests" / f"{name}.json"
        request = json.loads(path.read_text(encoding="utf-8"))
        user_payload = json.loads(request["messages"][1]["content"])
        user_payload["choice_contract"] = choice_contract.to_dict()
        user_payload["response_contract"]["predicted_choice"] = (
            "one exact string from choice_contract.compiled_options"
        )
        user_payload["constraints"]["do_not_invent_unregistered_combination"] = True
        request["messages"][1]["content"] = _cj(user_payload)
        request["response_contract"]["predicted_choice"] = (
            "one exact string from choice_contract.compiled_options"
        )
        path.write_text(
            json.dumps(request, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        request_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    receipt = {
        "schema": CHOICE_SCHEMA,
        "case_id": case_id,
        "base_manifest_sha256": manifest["manifest_sha256"],
        "choice_contract_sha256": choice_contract.contract_sha256,
        "request_sha256": request_hashes,
        "mode": "SHADOW",
        "execution_authority": "NONE",
        "can_execute": False,
    }
    receipt["receipt_sha256"] = _sha(receipt)
    (case_dir / "choice_contract_receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    return {
        "base_manifest": manifest,
        "choice_contract": choice_contract.to_dict(),
        "choice_contract_receipt": receipt,
    }
