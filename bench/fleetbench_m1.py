"""Source-tree wrapper for the packaged Governed Fleet M1 benchmark."""
from __future__ import annotations

import json

from continuityos.fleetbench_m1 import EXPECTED, run_fleetbench

__all__ = ["EXPECTED", "run_fleetbench"]


if __name__ == "__main__":
    print(json.dumps(run_fleetbench(), indent=2, sort_keys=True))
