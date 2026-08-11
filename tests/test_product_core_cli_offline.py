from __future__ import annotations

import json

from continuityos import current_entrypoints
from continuityos import embedders


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


def test_default_core_cos_never_constructs_fastembed(monkeypatch, tmp_path):
    _unbound(monkeypatch)
    monkeypatch.delenv("CONTINUITYOS_EMBEDDER", raising=False)
    calls = []

    class ForbiddenFastEmbed:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("FastEmbed must not be constructed by default")

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", ForbiddenFastEmbed)
    db = tmp_path / "memory.db"

    rc = current_entrypoints.cos_main(["--db", str(db), "remember", "offline marker"])

    assert rc == 0
    assert calls == []
    assert db.exists()


def test_fastembed_requires_explicit_opt_in(monkeypatch, tmp_path):
    _unbound(monkeypatch)
    monkeypatch.setenv("CONTINUITYOS_EMBEDDER", "fast")
    calls = []

    class FakeFastEmbed:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))

        def __call__(self, text):
            return [1.0, 0.0, 0.0]

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", FakeFastEmbed)
    db = tmp_path / "memory.db"

    rc = current_entrypoints.cos_main(["--db", str(db), "remember", "fast marker"])

    assert rc == 0
    assert len(calls) == 1
    assert db.exists()


def test_unknown_embedder_mode_holds_before_db_open(monkeypatch, tmp_path, capsys):
    _unbound(monkeypatch)
    monkeypatch.setenv("CONTINUITYOS_EMBEDDER", "surprise-provider")
    db = tmp_path / "must-not-exist.db"

    rc = current_entrypoints.cos_main(["--db", str(db), "remember", "blocked"])

    assert rc == 2
    assert not db.exists()
    value = json.loads(capsys.readouterr().out)
    assert value["terminal"] == "COS_EMBEDDER_POLICY_HOLD"
    assert value["reason"] == "UNSUPPORTED_EMBEDDER_MODE"
    assert value["requested"] == "surprise-provider"
    assert value["effects"]["network_effect"] is False
    assert value["effects"]["filesystem_write"] is False
    assert value["effects"]["memory_write"] is False


def test_bound_r64_blocks_before_fastembed_opt_in(monkeypatch, capsys):
    _bound(monkeypatch)
    monkeypatch.setenv("CONTINUITYOS_EMBEDDER", "fast")
    calls = []

    class ForbiddenFastEmbed:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("FastEmbed must not be constructed inside bound R64")

    monkeypatch.setattr(embedders, "FastEmbedEmbedder", ForbiddenFastEmbed)

    rc = current_entrypoints.cos_main(["remember", "blocked"])

    assert rc == 3
    assert calls == []
    value = json.loads(capsys.readouterr().out)
    assert value["terminal"] == "CURRENT_ENTRYPOINT_HOLD"
    assert value["authority_generation"] == "R64"
    assert value["legacy_fallback"] is False
    assert value["effects"]["network_effect"] is False


def test_product_help_documents_offline_default_and_fast_opt_in(monkeypatch, capsys):
    _unbound(monkeypatch)

    rc = current_entrypoints.cos_main(["--help"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "default embedder: local HashingEmbedder" in out
    assert "CONTINUITYOS_EMBEDDER=fast" in out
