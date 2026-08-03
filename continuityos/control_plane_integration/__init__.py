"""Packaged GitHub control-plane integration invariants.

The human-readable integration document remains in the source tree.  Runtime
and wheel-isolated validation use the packaged machine-readable manifest so
that policy assertions do not depend on source-only files.
"""

from __future__ import annotations

from importlib.resources import files
import json
from typing import Any


_EFFECT_CEILING_RESOURCE = "effect_ceiling_v1.json"


def load_effect_ceiling() -> dict[str, Any]:
    """Return the packaged, machine-readable effect ceiling.

    The function intentionally performs no filesystem mutation and no external
    I/O.  It reads only the resource shipped inside the installed package.
    """

    resource = files(__package__).joinpath(_EFFECT_CEILING_RESOURCE)
    value = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("effect ceiling resource must contain a JSON object")
    return value


__all__ = ["load_effect_ceiling"]
