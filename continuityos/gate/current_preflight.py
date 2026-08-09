"""Public gate preflight adapter with current-session monotonic containment."""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from ..current_effect_boundary import current_hold_for_action
from .engine import preflight as _legacy_preflight
from .ledger import Ledger as _LegacyLedger
from .spec import ActionSpec


def preflight(
    spec: ActionSpec,
    policy: Optional[Dict[str, Any]] = None,
    ledger: Optional[_LegacyLedger] = None,
    context=None,
) -> Dict[str, Any]:
    """Hold before legacy policy/ledger whenever a current session is declared."""
    hold = current_hold_for_action(spec.to_dict())
    if hold is not None:
        hold["ts"] = time.time()
        hold["context"]["supplied"] = context is not None
        return hold
    return _legacy_preflight(spec, policy=policy, ledger=ledger, context=context)
