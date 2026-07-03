"""Policy v0.1 — maps risk signals + protected paths to a decision.
Default policy ships in-code (zero deps). Load a YAML override if pyyaml is present."""
from __future__ import annotations
from typing import Dict, Any, List

DEFAULT_POLICY: Dict[str, Any] = {
    "version": "0.1",
    "protected_paths": [".git/*", ".git", "*.env", ".env", "*.pem", "id_rsa", "*.key",
                        "/etc/*", "~/*", "secrets/*", "*.sqlite", "*.db"],
    # severity -> decision when a dangerous command is detected
    "severity_decision": {
        "critical": "DENY",
        "high": "REQUIRE_CONFIRMATION",
        "medium": "WARN",
        "low": "ALLOW",
    },
    # if a write/delete touches a protected path -> this decision (takes the stricter of the two)
    "protected_path_decision": "REQUIRE_CONFIRMATION",
    # tools allowed to run at all (others -> HOLD for review)
    "allowed_tools": ["exec", "shell", "file.read", "file.write", "file.delete", "git", "http"],
    "default_decision": "ALLOW",
    # destructive shell with no detected pattern but on protected path can be forced to dry-run
    "dry_run_on_protected_delete": True,
}

def load_policy(path: str = "") -> Dict[str, Any]:
    if not path:
        return dict(DEFAULT_POLICY)
    try:
        import yaml  # optional
        with open(path, "r", encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
        merged = dict(DEFAULT_POLICY); merged.update(user)
        return merged
    except ImportError:
        raise ImportError("YAML policy needs pyyaml: pip install pyyaml (or use the built-in default)")
