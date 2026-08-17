from __future__ import annotations

import json
import sys

import pytest

from sct.errors import BenchError
from sct.runner.provider import SubprocessJsonRunner


def test_subprocess_runner_utf8_transport_preserves_non_ascii(tmp_path):
    child = tmp_path / "utf8_child.py"
    child.write_text(
        "import json,sys\n"
        "req=json.load(sys.stdin)\n"
        "text=req['messages'][0]['content']\n"
        "json.dump({'seen': text}, sys.stdout, ensure_ascii=True)\n",
        encoding="utf-8",
    )
    runner = SubprocessJsonRunner([sys.executable, str(child)])
    marker = "UTF-8 non\u2011breaking hyphen / Привет"
    out = runner.predict({"messages": [{"content": marker}]}, arm="generic")
    assert out["seen"] == marker


def test_distribution_dryrun_closes_sqlite_on_provider_failure(monkeypatch):
    import sct.dryrun as dryrun

    real_store = dryrun.SQLiteEvidenceStore

    class SpyStore(real_store):
        instances = []

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.closed_by_test = False
            type(self).instances.append(self)

        def close(self):
            self.closed_by_test = True
            return super().close()

    class FailingRunner:
        def predict(self, request, *, arm):
            raise BenchError("provider failed")

    monkeypatch.setattr(dryrun, "SQLiteEvidenceStore", SpyStore)
    with pytest.raises(BenchError):
        dryrun._run_distribution_dryrun(
            runner=FailingRunner(),
            cases=10,
            provider="test",
            model="test-model",
            model_version="v1",
            reason="VOID",
        )
    assert SpyStore.instances
    assert SpyStore.instances[0].closed_by_test is True


def test_openai_compatible_pre_call_delay_is_fixed_pacing(monkeypatch):
    import sct.runner.openai_compat as compat

    sleeps = []
    monkeypatch.setenv("SCT_OPENAI_COMPAT_PRECALL_DELAY_SECONDS", "3.2")
    monkeypatch.setattr(compat.time, "sleep", lambda seconds: sleeps.append(seconds))

    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self):
            content = json.dumps({
                "option_probabilities": {"A": 0.5, "B": 0.3, "C": 0.2},
                "reasons": ["test"],
                "change_conditions": [],
                "would_escalate": False,
            })
            return json.dumps({"choices": [{"message": {"content": content}}]}).encode("utf-8")

    monkeypatch.setenv("SCT_OPENAI_COMPAT_API_KEY", "test-secret")
    monkeypatch.setattr(compat.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    out = compat.call_openai_compatible({
        "model": "example/model",
        "messages": [{"role": "user", "content": "x"}],
        "token_budget": 128,
        "temperature": 0.0,
    })
    assert out["option_probabilities"]["A"] == pytest.approx(0.5)
    assert sleeps == [3.2]
