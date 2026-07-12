"""Policy loading and validation for the governance runner.

JSON is the zero-dependency on-disk format. YAML remains supported when PyYAML is
installed, but a missing parser or malformed policy is an error: silently falling
back to permissive defaults would make the configured boundary fictional.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
from typing import Dict, Any

from .spec import DECISIONS


class PolicyError(ValueError):
    """Raised when an explicit policy cannot be loaded or validated."""

DEFAULT_POLICY: Dict[str, Any] = {
    "version": "0.1",
    "protected_paths": [".git/*", ".git", "*.env", ".env", "*.pem", "id_rsa", "*.key",
                        "/etc/*", "~/*", "secrets/*", "*.sqlite", "*.db"],
    # severity -> decision when a dangerous command is detected
    "severity_decision": {
        "critical": "DENY",
        "high": "REQUIRE_CONFIRMATION",
        "medium": "REQUIRE_CONFIRMATION",
        "low": "ALLOW",
    },
    # if a write/delete touches a protected path -> this decision (takes the stricter of the two)
    "protected_path_decision": "REQUIRE_CONFIRMATION",
    # tools allowed to run at all (others -> HOLD for review)
    "allowed_tools": ["exec", "shell", "file.read", "file.write", "file.delete", "git", "http"],
    "default_decision": "ALLOW",
    # destructive shell with no detected pattern but on protected path can be forced to dry-run
    "dry_run_on_protected_delete": True,
    # Errors in continuity context must not silently erase a safety signal.
    "context_error_decision": "HOLD",
    "missing_paths_decision": "REQUIRE_CONFIRMATION",
    "missing_cwd_decision": "HOLD",
}


_DECISION_FIELDS = (
    "default_decision",
    "protected_path_decision",
    "capability_decision",
    "schema_decision",
    "context_error_decision",
    "missing_paths_decision",
    "missing_cwd_decision",
)

_TOP_LEVEL_FIELDS = set(DEFAULT_POLICY) | {
    "capabilities",
    "capability_decision",
    "schema_decision",
    "tool_schemas",
}
_TOOL_SCHEMA_FIELDS = {
    "allowed_domains",
    "allowed_roots",
    "forbid_patterns",
    "max_args",
}
_CAPABILITY_FIELDS = {"max_paths", "tools"}


def _reject_unknown_keys(mapping: Dict[str, Any], allowed: set[str], prefix: str) -> None:
    for key in mapping:
        if key not in allowed:
            raise PolicyError(f"unknown policy field: {prefix}.{key}")


def _validate_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(policy, dict):
        raise PolicyError("policy root must be an object/mapping")
    _reject_unknown_keys(policy, _TOP_LEVEL_FIELDS, "policy")
    if not isinstance(policy.get("version"), str) or not policy["version"].strip():
        raise PolicyError("policy.version must be a non-empty string")

    for field in _DECISION_FIELDS:
        if field in policy and policy[field] not in DECISIONS:
            raise PolicyError(f"policy.{field} must be one of {', '.join(DECISIONS)}")

    severity = policy.get("severity_decision")
    if not isinstance(severity, dict):
        raise PolicyError("policy.severity_decision must be an object/mapping")
    expected_severities = {"critical", "high", "medium", "low"}
    unknown_severities = set(severity) - expected_severities
    if unknown_severities:
        field = sorted(unknown_severities)[0]
        raise PolicyError(f"unknown policy field: policy.severity_decision.{field}")
    if set(severity) != expected_severities:
        raise PolicyError(
            "policy.severity_decision keys must be exactly: critical, high, medium, low"
        )
    for level, decision in severity.items():
        if not isinstance(level, str) or decision not in DECISIONS:
            raise PolicyError(f"invalid severity decision: {level!r} -> {decision!r}")

    for field in ("allowed_tools", "protected_paths"):
        values = policy.get(field)
        if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
            raise PolicyError(f"policy.{field} must be a list of non-empty strings")

    if not isinstance(policy.get("dry_run_on_protected_delete"), bool):
        raise PolicyError("policy.dry_run_on_protected_delete must be boolean")
    for field in ("tool_schemas", "capabilities"):
        if field in policy and not isinstance(policy[field], dict):
            raise PolicyError(f"policy.{field} must be an object/mapping")

    for tool, schema in policy.get("tool_schemas", {}).items():
        if not isinstance(tool, str) or not tool or not isinstance(schema, dict):
            raise PolicyError("each policy.tool_schemas entry must map a tool name to an object")
        _reject_unknown_keys(
            schema, _TOOL_SCHEMA_FIELDS, f"policy.tool_schemas.{tool}"
        )
        for field in ("forbid_patterns", "allowed_roots", "allowed_domains"):
            if field in schema:
                values = schema[field]
                if not isinstance(values, list) or any(
                    not isinstance(value, str) or not value for value in values
                ):
                    raise PolicyError(
                        f"policy.tool_schemas.{tool}.{field} must be a list of non-empty strings"
                    )
        if "max_args" in schema and (
            isinstance(schema["max_args"], bool)
            or not isinstance(schema["max_args"], int)
            or schema["max_args"] < 0
        ):
            raise PolicyError(f"policy.tool_schemas.{tool}.max_args must be a non-negative integer")

    for agent, passport in policy.get("capabilities", {}).items():
        if not isinstance(agent, str) or not agent or not isinstance(passport, dict):
            raise PolicyError("each policy.capabilities entry must map an agent name to an object")
        _reject_unknown_keys(
            passport, _CAPABILITY_FIELDS, f"policy.capabilities.{agent}"
        )
        if "tools" in passport:
            tools = passport["tools"]
            if not isinstance(tools, list) or any(
                not isinstance(tool, str) or not tool for tool in tools
            ):
                raise PolicyError(
                    f"policy.capabilities.{agent}.tools must be a list of non-empty strings"
                )
        if "max_paths" in passport and (
            isinstance(passport["max_paths"], bool)
            or not isinstance(passport["max_paths"], int)
            or passport["max_paths"] < 0
        ):
            raise PolicyError(
                f"policy.capabilities.{agent}.max_paths must be a non-negative integer"
            )
    return policy


def default_policy() -> Dict[str, Any]:
    """Return an isolated copy so callers cannot mutate the process default."""
    return copy.deepcopy(DEFAULT_POLICY)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def load_policy(path: str = "") -> Dict[str, Any]:
    if not path:
        return _validate_policy(default_policy())

    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(path):
        raise PolicyError(f"policy file not found: {path}")
    suffix = os.path.splitext(path)[1].lower()
    try:
        with open(path, "r", encoding="utf-8") as f:
            if suffix == ".json":
                user = json.load(f)
            elif suffix in (".yaml", ".yml"):
                try:
                    import yaml  # type: ignore
                except ImportError as exc:
                    raise PolicyError(
                        "YAML policy requires PyYAML; use policy.json for the zero-dependency format"
                    ) from exc
                user = yaml.safe_load(f)
            else:
                raise PolicyError("policy format must be .json, .yaml, or .yml")
    except PolicyError:
        raise
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise PolicyError(f"cannot load policy {path}: {exc}") from exc
    except Exception as exc:
        # PyYAML exposes parser-specific exception types; keep the public error stable.
        raise PolicyError(f"cannot parse policy {path}: {exc}") from exc

    if user is None:
        user = {}
    if not isinstance(user, dict):
        raise PolicyError("policy root must be an object/mapping")
    merged = _deep_merge(default_policy(), user)
    return _validate_policy(merged)


def discover_policy(home: str) -> str:
    """Find one runtime policy deterministically; ambiguity fails closed."""
    candidates = [
        os.path.join(home, "policy.json"),
        os.path.join(home, "policy.yaml"),
        os.path.join(home, "policy.yml"),
    ]
    found = [p for p in candidates if os.path.isfile(p)]
    if len(found) > 1:
        raise PolicyError("multiple policy files found; keep exactly one: " + ", ".join(found))
    return found[0] if found else ""


def policy_fingerprint(policy: Dict[str, Any]) -> str:
    """Stable SHA-256 identifier used in decision traces (not a signature)."""
    body = json.dumps(policy, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
