"""ContinuityOS Gate — AI Agent Governance Gateway (hard-boundary preflight).
No registered dangerous tool may execute unless a ContinuityOS preflight decision exists."""
from .spec import ActionSpec, DECISIONS
from .engine import preflight
from .ledger import Ledger
from .policy import load_policy, DEFAULT_POLICY
__all__ = ["ActionSpec", "DECISIONS", "preflight", "Ledger", "load_policy", "DEFAULT_POLICY"]
