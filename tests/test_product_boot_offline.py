from __future__ import annotations

import json

from continuityos import current_entrypoints
from continuityos.continuity import Continuity
from continuityos.memory import Memory
import continuityos.updater as updater


def _db(tmp_path):
    path = tmp_path / "memory.db"
    memory = Memory(str(path))
    continuity = Continuity(memory=memory)
    continuity.add_canon("offline boot marker")
    return path


def _unbound(monkeypatch) -> None:
    monkeypatch.setattr(current_entrypoints, "current_binding_from_env", lambda env: (None, []))


def _bound(monkeypatch) -> None:
    monkeypatch.setattr(
        current_entrypoints,
        "current_binding_from_env",
        lambda env: ({"challenge": "x", "ack": "y", "challenge_sha256": "z"}, []),
    )
    monkeypatch.setattr(
        current_entrypoints,
        "_verify_binding",
        lambda binding, surface, command: (
            {
                "binding_verified": True,
                "authority_generation": "R64",
                "challenge_id": "cid",
                "challenge_sha256": "sha",
            },
            None,
        ),
    )


def test_boot_default_never_calls_updater_or_fastembed(monkeypatch, tmp_path, capsys):
    _unbound(monkeypatch)
    db = _db(tmp_path)
    cache = tmp_path / "update_check.json"
    monkeypatch.setattr(updater, "CACHE", str(cache))
    monkeypatch.setattr(
        updater,
        "check",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("updater called during offline boot")),
    )

    from continuityos import embedders

    monkeypatch.setattr(
        embedders,
        "FastEmbedEmbedder",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("FastEmbed constructed during offline boot")),
    )

    rc = current_entrypoints.cos_main(["--db", str(db), "boot"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "--- doctor ---" in out
    assert "offline boot marker" in out
    assert "[update" not in out
    assert not cache.exists()


def test_boot_check_updates_is_explicit_and_force_checked(monkeypatch, tmp_path, capsys):
    _unbound(monkeypatch)
    db = _db(tmp_path)
    calls = []

    def fake_check(*, force=False, ttl=86400.0):
        calls.append({"force": force, "ttl": ttl})
        return {
            "current": "0.10.0",
            "latest": "0.10.0",
            "update_available": False,
            "cached": False,
        }

    monkeypatch.setattr(updater, "check", fake_check)

    rc = current_entrypoints.cos_main(["--db", str(db), "boot", "--check-updates"])

    assert rc == 0
    assert calls == [{"force": True, "ttl": 86400.0}]
    assert "[update check] 0.10.0 is current (PyPI 0.10.0)" in capsys.readouterr().out


def test_boot_missing_db_holds_before_update_check(monkeypatch, tmp_path, capsys):
    _unbound(monkeypatch)
    missing = tmp_path / "missing.db"
    monkeypatch.setattr(
        updater,
        "check",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("updater called before DB validation")),
    )

    rc = current_entrypoints.cos_main(["--db", str(missing), "boot", "--check-updates"])

    assert rc == 2
    out = capsys.readouterr().out
    assert "COS_BOOT_HOLD: MEMORY_DB_NOT_FOUND" in out
    assert "run: cos setup" in out


def test_bound_r64_blocks_boot_before_network_path(monkeypatch, capsys):
    _bound(monkeypatch)
    monkeypatch.setattr(
        updater,
        "check",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("updater called inside bound R64")),
    )

    rc = current_entrypoints.cos_main(["boot", "--check-updates"])

    assert rc == 3
    value = json.loads(capsys.readouterr().out)
    assert value["terminal"] == "CURRENT_ENTRYPOINT_HOLD"
    assert value["authority_generation"] == "R64"
    assert value["legacy_fallback"] is False
    assert value["effects"]["network_effect"] is False
    assert value["effects"]["filesystem_write"] is False
    assert value["effects"]["memory_write"] is False
