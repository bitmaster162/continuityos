from __future__ import annotations

import json

from continuityos.sovereign_twin_cli import _emit


def test_cli_emit_is_ascii_safe_and_round_trips_unicode(capsys):
    payload = {
        "text": "архитектура — память",
        "evidence": [{"text": "данные 🌐"}],
        "execution_authority": "NONE",
        "can_execute": False,
    }

    code = _emit(payload)
    raw = capsys.readouterr().out.strip()

    assert code == 0
    raw.encode("ascii")
    assert json.loads(raw) == payload
    assert "\\u" in raw
