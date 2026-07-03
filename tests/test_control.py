import json
import os
import tempfile

import pytest

from continuityos import ControlPlane, Memory


def _m():
    d = tempfile.mkdtemp()
    return Memory(os.path.join(d, "control.db"))


def test_correct_supersedes_without_deleting_original():
    m = _m()
    ctl = ControlPlane(memory=m)

    old_id = m.remember("The API token is stored in notes", namespace="facts")
    new_id = ctl.correct(old_id, "The API token must never be stored in notes", namespace="facts")

    old = m.store.get(old_id)
    new = m.store.get(new_id)

    assert old is not None
    assert new is not None
    assert m.count() == 3  # old + corrected + control log

    old_meta = json.loads(old["meta"])
    new_meta = json.loads(new["meta"])

    assert old_meta["superseded_by"] == new_id
    assert "valid_to" in old_meta
    assert new_meta["supersedes"] == old_id


def test_corrected_item_is_current_and_old_item_is_not_current():
    m = _m()
    ctl = ControlPlane(memory=m)

    old_id = m.remember("Ship version 0.7.0", namespace="facts")
    new_id = ctl.correct(old_id, "Ship version 0.8.1", namespace="facts")

    hits = m.recall("ship version", k=10, namespace="facts", current_only=True)
    ids = {h.id for h in hits}

    assert new_id in ids
    assert old_id not in ids


def test_correct_missing_item_raises_keyerror():
    ctl = ControlPlane(memory=_m())
    with pytest.raises(KeyError):
        ctl.correct(999, "replacement", namespace="facts")
