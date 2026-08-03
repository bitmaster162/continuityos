"""Packaged machine-readable policy manifests for ContinuityOS control gates.

Human-readable documents remain in the source tree.  Installed-wheel and
wheel-isolated verification read these resources, so policy assertions do not
depend on source-only files such as ``pyproject.toml`` or ``docs/``.
"""

from __future__ import annotations

from importlib.resources import files
import json
from typing import Any


_POLICY_RESOURCES = {
    "completion_claim": "completion_claim_policy_v1.json",
    "work_ledger_review_binding": "work_ledger_review_binding_policy_v1.json",
    "merge_authorization": "merge_authorization_policy_v1.json",
}


def load_policy(name: str) -> dict[str, Any]:
    """Load one packaged policy manifest by stable logical name."""

    try:
        resource_name = _POLICY_RESOURCES[name]
    except KeyError as exc:
        raise ValueError(f"unknown control-plane policy: {name}") from exc
    resource = files(__package__).joinpath(resource_name)
    value = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"control-plane policy {name} must be a JSON object")
    return value


def policy_names() -> tuple[str, ...]:
    """Return the stable logical names in deterministic order."""

    return tuple(sorted(_POLICY_RESOURCES))


__all__ = ["load_policy", "policy_names"]
