#!/usr/bin/env python3
"""ContinuityOS demo: append-only ledger detects tampering."""
from __future__ import annotations

import os
import tempfile

from continuityos.gate import ActionSpec, Ledger, preflight


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="cos-ledger-demo-")
    ledger_path = os.path.join(tmp, "ledger.db")
    ledger = Ledger(ledger_path)

    preflight(ActionSpec(tool="shell", command="rm -rf /"), ledger=ledger)
    before = ledger.verify()
    print("before tamper:", before)

    ledger.con.execute(
        "UPDATE events SET payload=? WHERE id=1",
        ('{"decision":"ALLOW","command":"rm -rf /"}',),
    )
    ledger.con.commit()

    after = ledger.verify()
    print("after tamper:", after)

    if before.get("ok") is True and after.get("ok") is False:
        print("OK: tampering detected")
        return 0

    print("ERROR: expected ledger verification to fail after tamper")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
