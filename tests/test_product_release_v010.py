from __future__ import annotations

import json

from continuityos import current_entrypoints
from continuityos._version import __version__


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


def test_v0101_canonical_version():
    assert __version__ == "0.10.1"


def test_cos_help_is_product_first_unbound(monkeypatch, capsys):
    _unbound(monkeypatch)

    rc = current_entrypoints.cos_main(["--help"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "ContinuityOS — local-first durable memory + continuity" in out
    assert "connect [client]" in out
    assert "status" in out
    assert "demo continuity" in out
    assert "setup" in out
    assert "import <path>" in out
    assert "boot" in out


def test_cos_short_help_is_product_first_unbound(monkeypatch, capsys):
    _unbound(monkeypatch)

    rc = current_entrypoints.cos_main(["-h"])

    assert rc == 0
    assert "demo continuity" in capsys.readouterr().out


def test_cos_version_reports_canonical_package_version_unbound(monkeypatch, capsys):
    _unbound(monkeypatch)

    rc = current_entrypoints.cos_main(["--version"])

    assert rc == 0
    assert capsys.readouterr().out.strip() == "continuityos 0.10.1"


def test_cos_help_cannot_bypass_bound_r64(monkeypatch, capsys):
    _bound(monkeypatch)

    rc = current_entrypoints.cos_main(["--help"])

    assert rc == 3
    value = json.loads(capsys.readouterr().out)
    assert value["terminal"] == "CURRENT_ENTRYPOINT_HOLD"
    assert value["binding_verified"] is True
    assert value["authority_generation"] == "R64"
    assert value["effects"]["filesystem_write"] is False
    assert value["effects"]["memory_write"] is False


def test_cos_version_cannot_bypass_bound_r64(monkeypatch, capsys):
    _bound(monkeypatch)

    rc = current_entrypoints.cos_main(["--version"])

    assert rc == 3
    value = json.loads(capsys.readouterr().out)
    assert value["terminal"] == "CURRENT_ENTRYPOINT_HOLD"
    assert value["legacy_fallback"] is False
    assert value["effects"]["network_effect"] is False
    assert value["effects"]["deployment"] is False
