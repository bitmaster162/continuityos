"""Offline tests for the migration adapters (cos import). Zero external deps/keys."""
import os, json, tempfile
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
from continuityos.memory import Memory
from continuityos.adapters import (parse_chatgpt, parse_claude, sniff,
                                   import_path, import_records)

T1, T2, T3 = 1700000000.0, 1700000100.0, 1700000200.0

def _chatgpt():
    return [{"title": "Trading", "conversation_id": "c1", "mapping": {
        "n1": {"message": {"author": {"role": "user"}, "create_time": T1,
               "content": {"content_type": "text", "parts": ["I prefer Apache-2.0 licenses for my OSS projects."]}}},
        "n2": {"message": {"author": {"role": "assistant"}, "create_time": T2,
               "content": {"content_type": "text", "parts": ["Noted."]}}},
        "n3": {"message": {"author": {"role": "user"}, "create_time": T3,
               "content": {"content_type": "text", "parts": ["We decided to launch on Show HN on Tuesday."]}}},
    }}]

def _claude_conv():
    return [{"name": "Arena", "uuid": "u1", "created_at": "2026-06-01T10:00:00Z", "chat_messages": [
        {"sender": "human", "created_at": "2026-06-01T10:00:00Z", "text": "My arena runs 150 paper bots on Bybit."},
        {"sender": "assistant", "created_at": "2026-06-01T10:01:00Z", "text": "Understood, noted."},
    ]}]

def _claude_mem():
    return ["Robert's timezone is UTC+7.", "The trunk canon lives in the PROJECTS folder."]

def _write(tmp, name, obj):
    p = os.path.join(tmp, name)
    json.dump(obj, open(p, "w", encoding="utf-8"))
    return p

def _mem():
    d = tempfile.mkdtemp()
    return Memory(os.path.join(d, "m.db"))

def test_parse_chatgpt_order_roles_ts():
    r = parse_chatgpt(_chatgpt())
    assert [x.role for x in r] == ["user", "assistant", "user"], r
    assert r[0].ts == T1 and r[2].ts == T3
    assert "Apache-2.0" in r[0].text and r[0].source == "chatgpt"
    print("PASS parse_chatgpt_order_roles_ts")

def test_sniff():
    assert sniff(_chatgpt()) == "chatgpt"
    assert sniff(_claude_conv()) == "claude"
    assert sniff(_claude_mem()) == "claude"
    print("PASS sniff")

def test_import_chatgpt_useronly_bitemporal():
    tmp = tempfile.mkdtemp(); p = _write(tmp, "conversations.json", _chatgpt())
    m = _mem()
    res = import_path(p, m, namespace="imported")
    assert res.imported == 2, res.as_dict()          # 2 user msgs; assistant "Noted." excluded
    assert res.source == "chatgpt"
    hits = m.recall("what license do I like?", namespace="imported")
    assert any("Apache-2.0" in h.text for h in hits), [h.text for h in hits]
    # bi-temporal: nothing was true BEFORE the first message
    assert m.recall("license", namespace="imported", as_of=T1 - 1) == []
    # at T1+50 only the first fact is valid, not the T3 one
    mid = m.recall("launch", namespace="imported", as_of=T1 + 50)
    assert all("Show HN" not in h.text for h in mid), [h.text for h in mid]
    # valid_from persisted
    all_hits = m.recall("Apache", namespace="imported")
    assert any(h.meta.get("valid_from") == T1 for h in all_hits)
    print("PASS import_chatgpt_useronly_bitemporal")

def test_import_claude_conversations():
    tmp = tempfile.mkdtemp(); p = _write(tmp, "conversations.json", _claude_conv())
    m = _mem()
    res = import_path(p, m, namespace="imported", source="claude")
    assert res.imported == 1, res.as_dict()          # human only; assistant excluded
    assert any("paper bots" in h.text for h in m.recall("bots", namespace="imported"))
    print("PASS import_claude_conversations")

def test_import_claude_memories_strings():
    tmp = tempfile.mkdtemp(); p = _write(tmp, "memories.json", _claude_mem())
    m = _mem()
    res = import_path(p, m, namespace="imported", source="claude")
    assert res.imported == 2, res.as_dict()
    assert any("UTC+7" in h.text for h in m.recall("timezone", namespace="imported"))
    print("PASS import_claude_memories_strings")

def test_dry_run_no_write():
    tmp = tempfile.mkdtemp(); p = _write(tmp, "conversations.json", _chatgpt())
    m = _mem(); before = m.count()
    res = import_path(p, m, namespace="imported", dry_run=True)
    assert res.imported == 2 and m.count() == before, (res.as_dict(), m.count())
    print("PASS dry_run_no_write")

def test_dedupe_second_import():
    tmp = tempfile.mkdtemp(); p = _write(tmp, "conversations.json", _chatgpt())
    m = _mem()
    import_path(p, m, namespace="imported")
    res2 = import_path(p, m, namespace="imported")
    assert res2.imported == 0 and res2.skipped_dup == 2, res2.as_dict()
    print("PASS dedupe_second_import")

def test_extract_mode_distills_typed():
    tmp = tempfile.mkdtemp(); p = _write(tmp, "conversations.json", _chatgpt())
    m = _mem()
    res = import_path(p, m, namespace="facts", extract_mode=True)
    assert res.imported >= 1, res.as_dict()
    types = [h.meta.get("type") for h in m.recall("launch decision preference", namespace="facts", k=10)]
    assert any(t in ("decision", "preference", "goal", "fact", "event") for t in types), types
    print("PASS extract_mode_distills_typed")

def run():
    for name in sorted(n for n in globals() if n.startswith("test_")):
        globals()[name]()
    print("ALL_ADAPTER_TESTS_PASS")

if __name__ == "__main__":
    run()
