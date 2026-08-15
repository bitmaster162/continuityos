from __future__ import annotations

import json
from pathlib import Path

from continuityos.operational_memory import OperationalMemory

H1 = "1" * 64
H2 = "2" * 64


def _write_registry(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_r59_delivery_verified_maps_to_physical_acceptance_without_semantic_promotion(tmp_path: Path):
    registry = tmp_path / "MASTER_RETURN_REGISTRY_R59.jsonl"
    _write_registry(
        registry,
        [{
            "delivery_id": "delivery-r59-1",
            "zip_sha256": H1,
            "generation": "R59",
            "slot": "CODEX-01",
            "work_order_id": "WO-R59-1",
            "status": "DELIVERY_VERIFIED",
            "content_status": "ACCEPTED",
            "apply_status": "APPLIED",
        }],
    )

    with OperationalMemory(str(tmp_path / "opmem.db")) as db:
        first = db.import_broker_registry(registry)
        second = db.import_broker_registry(registry)
        row = db.con.execute(
            "SELECT physical_status, content_status, apply_status "
            "FROM broker_custody WHERE delivery_id=?",
            ("delivery-r59-1",),
        ).fetchone()

        assert first["inserted"] == 1
        assert second["inserted"] == 0
        assert second["duplicates"] == 1
        assert tuple(row) == ("PHYSICALLY_ACCEPTED", "UNREVIEWED", "NOT_APPLIED")

        projection = db.projection()
        assert projection["ceilings"]["content_acceptance"] == "NOT_PERFORMED"
        assert projection["ceilings"]["state_apply"] == "DISABLED"
        assert projection["ceilings"]["can_trade"] is False


def test_unknown_broker_status_still_fails_down_to_reported(tmp_path: Path):
    registry = tmp_path / "unknown.jsonl"
    _write_registry(
        registry,
        [{
            "delivery_id": "delivery-unknown-1",
            "zip_sha256": H2,
            "status": "SOME_NEW_UNTRUSTED_PROSE",
        }],
    )

    with OperationalMemory(str(tmp_path / "opmem.db")) as db:
        db.import_broker_registry(registry)
        row = db.con.execute(
            "SELECT physical_status, content_status, apply_status "
            "FROM broker_custody WHERE delivery_id=?",
            ("delivery-unknown-1",),
        ).fetchone()
        assert tuple(row) == ("REPORTED", "UNREVIEWED", "NOT_APPLIED")
