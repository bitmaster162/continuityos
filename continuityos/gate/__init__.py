"""ContinuityOS governance decisions and controlled-runner primitives.

The library is a boundary only when an executor or host hook is explicitly wired to
honor its decision; importing or exposing ``preflight`` does not intercept other tools.
"""
from .spec import ActionSpec, DECISIONS
from .engine import preflight
from .ledger import Ledger
from .policy import load_policy, DEFAULT_POLICY, PolicyError
__all__ = ["ActionSpec", "DECISIONS", "preflight", "Ledger", "load_policy", "DEFAULT_POLICY", "PolicyError"]
