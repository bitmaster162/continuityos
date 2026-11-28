"""A rules export cannot use an entry-time allowance after its ceiling changes."""
import pytest

from continuityos import current_effect_boundary as boundary
from continuityos import rules_export


def test_export_rechecks_effect_ceiling_after_gather(tmp_path, monkeypatch):
    for name in (boundary.ENV_CHALLENGE, boundary.ENV_CHALLENGE_SHA,
                 boundary.ENV_ACK, boundary.ENV_REQUIRED):
        monkeypatch.delenv(name, raising=False)
    def gather(_memory):
        monkeypatch.setenv(boundary.ENV_REQUIRED, "1")
        return ["unverified local rule"], [], {}
    monkeypatch.setattr(rules_export, "_gather", gather)
    output = tmp_path / "must-remain-missing"
    with pytest.raises(boundary.CurrentEffectBoundaryError):
        rules_export.export_rules(object(), out_dir=str(output), targets=("agents",))
    assert not output.exists()
