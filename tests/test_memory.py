import os, tempfile
from continuityos import Memory

def _m():
    d = tempfile.mkdtemp()
    return Memory(os.path.join(d, "t.db"))

def test_remember_and_count():
    m = _m()
    rid = m.remember("Apache-2.0 is a permissive license", namespace="rules")
    assert isinstance(rid, int) and rid > 0
    assert m.count() == 1

def test_hybrid_recall_finds_by_meaning():
    m = _m()
    m.remember("Robert prefers Apache-2.0 licenses", namespace="rules")
    m.remember("Cat photos from the beach", namespace="notes")
    hits = m.recall("which software license should I use?", k=1)
    assert hits and hits[0].namespace == "rules"

def test_namespace_filter():
    m = _m()
    m.remember("grid bot K=0.04", namespace="facts")
    m.remember("grid bot in notes", namespace="notes")
    hits = m.recall("grid bot", k=5, namespace="facts")
    assert all(h.namespace == "facts" for h in hits)

def test_forget():
    m = _m()
    rid = m.remember("temporary memory", namespace="notes")
    assert m.forget(rid)
    assert m.count() == 0

def test_context_block():
    m = _m()
    m.remember("ContinuityOS is hybrid memory", namespace="projects")
    ctx = m.context("what is the product?", k=2)
    assert "ContinuityOS" in ctx
