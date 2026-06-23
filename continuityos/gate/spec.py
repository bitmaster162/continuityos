"""ActionSpec — the typed description of what an agent wants to do, before it does it.
ContinuityOS preflight() consumes this and returns a Decision."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

@dataclass
class ActionSpec:
    tool: str                                  # e.g. "shell", "file.write", "http", "git"
    command: str = ""                          # raw command / intent string
    args: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)   # filesystem targets
    cwd: str = ""
    agent: str = "unknown"                     # which agent/session is asking
    meta: Dict[str, Any] = field(default_factory=dict)
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

DECISIONS = ("ALLOW", "WARN", "HOLD", "DENY", "REQUIRE_CONFIRMATION", "DRY_RUN_ONLY")
