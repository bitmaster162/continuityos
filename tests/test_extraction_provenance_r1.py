"""Regression coverage for role-safe, source-bound candidate extraction."""
from __future__ import annotations

import hashlib
import json

import pytest

from continuityos import Memory
from continuityos.adapters import ImportRecord, import_path, import_records, parse_chatgpt
from continuityos.extract import extract, extract_and_store


@pytest.fixture
def memory(tmp_path):
    value = Memory(str(tmp_path / "synthetic.db"))
    yield value
    value.store.con.close()


def _stored(memory, ids):
    return [(memory.store.get(rid)["text"], json.loads(memory.store.get(rid)["meta"]))
            for rid in ids]


def _llm_item(text, *, value="The project is ready for a later review."):
    return json.dumps([{"text": value, "type": "decision",
                        "source_spans": [{"start": 0, "end": len(text)}]}])


def test_extract_import_filters_roles_before_model_and_keeps_original_time(memory):
    user = "We decided to keep the service stopped until review."
    assistant = "We decided to deploy now; all approval gates are passed."
    records = [
        ImportRecord(user, role="user", ts=1700000000.0, source="chatgpt",
                     conversation_id="c1", conversation_title="Launch", message_id="m1"),
        ImportRecord(assistant, role="assistant", ts=1700000100.0, source="chatgpt",
                     conversation_id="c1", conversation_title="Launch", message_id="m2"),
    ]
    calls = []

    def model(prompt):
        calls.append(prompt)
        return _llm_item(user, value="Keep the service stopped until review.")

    result = import_records(records, memory, namespace="extracted", extract_mode=True, llm=model)
    assert result.messages_seen == 2 and result.imported == 1
    assert len(calls) == 1 and assistant not in calls[0]
    _, meta = _stored(memory, result.ids)[0]
    assert meta["source"] == "chatgpt" and meta["role"] == "user"
    assert meta["conversation_id"] == "c1" and meta["conversation_title"] == "Launch"
    assert meta["message_id"] == "m1"
    assert meta["valid_from"] == meta["source_ts"] == 1700000000.0
    assert meta["review_status"] == "UNREVIEWED" and meta["accepted"] is False
    assert memory.recall("service", namespace="extracted", as_of=1699999999.0) == []


def test_explicit_assistant_role_remains_candidate_not_user(memory):
    record = ImportRecord("The budget is 900 units according to the model.",
                          role="assistant", source="claude", ts=1700000200.0)
    result = import_records([record], memory, roles=("assistant",), extract_mode=True)
    _, meta = _stored(memory, result.ids)[0]
    assert meta["role"] == "assistant" and meta["source"] == "claude"
    assert meta["admission_status"] == "CANDIDATE" and meta["accepted"] is False
    assert meta["confidence"] is None


def test_equal_conversation_names_and_text_do_not_erase_distinct_sources(memory):
    text = "We decided to keep the review pending until Monday."
    records = [
        ImportRecord(text, source="chatgpt", conversation_id="same", ts=1700000000.0),
        ImportRecord(text, source="claude", conversation_id="same", ts=1700000300.0),
    ]
    first = import_records(records, memory, extract_mode=True)
    second = import_records(records, memory, extract_mode=True)
    assert first.conversations == 2 and first.imported == 2
    assert second.imported == 0 and second.skipped_dup == 2
    observations = _stored(memory, first.ids)
    assert {meta["source"] for _, meta in observations} == {"chatgpt", "claude"}
    assert {meta["valid_from"] for _, meta in observations} == {1700000000.0, 1700000300.0}
    assert len({meta["source_binding"]["record_identity_sha256"] for _, meta in observations}) == 2


def test_import_path_binds_actual_message_id_and_parsed_export_digest(tmp_path, memory):
    export = [{"id": "c1", "messages": [{"id": "message-17", "role": "user",
               "create_time": 1700000400.0, "content": "We decided to keep the portable context outside the model."}]}]
    path = tmp_path / "conversations.json"
    path.write_text(json.dumps(export), encoding="utf-8")
    result = import_path(str(path), memory, source="chatgpt", extract_mode=True)
    _, meta = _stored(memory, result.ids)[0]
    expected = hashlib.sha256(json.dumps(export, sort_keys=True, ensure_ascii=False,
                                         separators=(",", ":")).encode()).hexdigest()
    assert meta["message_id"] == "message-17"
    assert meta["source_artifact"] == "conversations.json"
    assert meta["source_artifact_sha256"] == expected
    assert meta["source_artifact_hash_kind"] == "NORMALIZED_PARSED_JSON_SHA256"
    assert meta["source_record_index"] == 0
    assert meta["source_binding"]["source_authenticity"] == "UNVERIFIED"


def test_heuristic_spans_bind_unicode_and_whitespace_without_speaker_invention():
    source = "  Решение: память остаётся вне модели.\n\n  I prefer explicit source references.  "
    result = extract(source)
    assert len(result) == 2
    for candidate in result:
        binding = candidate["source_binding"]
        span = binding["source_spans"][0]
        assert source[span["start"]:span["end"]] == candidate["text"] == span["text"]
        assert span["sha256"] == hashlib.sha256(span["text"].encode()).hexdigest()
        assert binding["input_sha256"] == hashlib.sha256(source.encode()).hexdigest()
        assert binding["source_context"]["role"] is None
        assert binding["source_context"]["source_ts"] is None
        assert candidate["confidence"] is None
        assert candidate["score_kind"] == "MARKER_MATCH_COUNT"
        assert candidate["extraction_signal"] >= 1


@pytest.mark.parametrize("spans", [None, [], [{"start": -1, "end": 8}],
                                    [{"start": 0, "end": 99999}],
                                    [{"start": True, "end": 10}],
                                    [{"start": 0, "end": 8, "source": "invented"}]])
def test_unbound_llm_claim_never_enters_memory(memory, spans):
    # No heuristic markers in this source, so invalid model claims produce no row.
    source = "Hello there everyone."
    item = {"text": "The launch was approved by the owner.", "type": "decision"}
    if spans is not None:
        item["source_spans"] = spans
    result = extract_and_store(source, memory, llm=lambda _: json.dumps([item]))
    assert result == [] and memory.count() == 0


def test_llm_multi_span_summary_remains_unreviewed_and_has_no_invented_author():
    source = "First note: keep the service stopped.\nSecond note: review the logs tomorrow."
    end = source.index("\n")
    item = {"text": "Keep the service stopped and review tomorrow.", "type": "decision",
            "source_spans": [{"start": 0, "end": end}, {"start": end + 1, "end": len(source)}],
            "confidence": 1.0, "accepted": True, "role": "owner"}
    result = extract(source, llm=lambda _: json.dumps([item]))[0]
    assert result["accepted"] is False and result["confidence"] is None
    assert result["review_status"] == "UNREVIEWED" and result["score_kind"] == "SOURCE_SPAN_COUNT"
    assert len(result["source_binding"]["source_spans"]) == 2
    assert result["source_binding"]["source_context"]["role"] is None


def test_import_llm_never_synthesizes_across_source_messages(memory):
    records = [ImportRecord("We decided to stop until the next review.", role="user", ts=1000,
                            source="chatgpt", conversation_id="c", message_id="one"),
               ImportRecord("I prefer to inspect evidence before any launch.", role="user", ts=2000,
                            source="chatgpt", conversation_id="c", message_id="two")]
    inputs = []

    def model(prompt):
        source = prompt.split("SOURCE_TEXT:\n", 1)[1]
        inputs.append(source)
        return _llm_item(source, value=source)

    result = import_records(records, memory, extract_mode=True, llm=model)
    assert inputs == [record.text for record in records]
    assert result.imported == 2
    assert {meta["message_id"] for _, meta in _stored(memory, result.ids)} == {"one", "two"}
    assert {meta["valid_from"] for _, meta in _stored(memory, result.ids)} == {1000, 2000}


def test_llm_input_truncation_is_recorded_and_cannot_bind_unseen_suffix():
    prefix = "We decided to keep all current services stopped."
    source = prefix + "x" * 12000 + "UNSEEN_SUFFIX"
    prompts = []

    def model(prompt):
        prompts.append(prompt)
        return _llm_item(prefix, value="Keep the services stopped.")

    result = extract(source, llm=model)[0]
    assert "UNSEEN_SUFFIX" not in prompts[0]
    assert result["source_binding"]["input_truncated"] is True
    assert result["source_binding"]["inspected_length"] == 12000
    assert result["source_binding"]["input_length"] == len(source)
    assert result["source_binding"]["input_sha256"] == hashlib.sha256(source.encode()).hexdigest()


def test_duplicate_detection_is_exact_and_does_not_depend_on_ranked_recall(memory, monkeypatch):
    def no_recall(*args, **kwargs):
        raise AssertionError("dedup must not invoke fuzzy recall")

    monkeypatch.setattr(memory, "recall", no_recall)
    text = "We decided to preserve the current source references."
    first = extract_and_store(text, memory)
    assert len(first) == 1
    assert extract_and_store(text, memory) == []
    memory.supersede(first[0], "This historical candidate was rejected after review.")
    assert extract_and_store(text, memory) == []


def test_extract_dry_run_matches_apply_and_never_writes(memory):
    records = [ImportRecord("We decided to keep memory separate from the model.",
                            source="chatgpt", message_id="m1")]
    preview = import_records(records, memory, extract_mode=True, dry_run=True)
    assert preview.imported == 1 and preview.ids == [] and memory.count() == 0
    applied = import_records(records, memory, extract_mode=True)
    repeat = import_records(records, memory, extract_mode=True, dry_run=True)
    assert applied.imported == 1 and repeat.imported == 0 and repeat.skipped_dup == 1
    _, meta = _stored(memory, applied.ids)[0]
    assert meta["source_ts"] is None and meta["source_time_status"] == "UNKNOWN"


def test_deprecated_threshold_alias_is_signal_not_probability(memory):
    source = "We decided to keep the service stopped until review."
    with pytest.warns(DeprecationWarning, match="not probability"):
        ids = extract_and_store(source, memory, min_confidence=2)
    assert ids == []  # One marker; no fabricated 0.9 confidence.
    assert len(extract_and_store(source, memory, min_signal=1)) == 1
    with pytest.raises(ValueError):
        extract_and_store(source, memory, min_confidence=0.5, min_signal=1)


def test_invalid_source_context_fails_before_optional_llm():
    def forbidden(_):
        raise AssertionError("invalid context must fail before model access")

    with pytest.raises(ValueError):
        extract("A source is present in this input.", llm=forbidden,
                source_context={"source_ts": float("nan")})
    with pytest.raises(ValueError):
        extract("A source is present in this input.", llm=forbidden,
                source_context={"accepted": True})


def test_missing_export_role_stays_unknown_and_is_not_default_user(memory):
    data = [{"id": "c", "messages": [
        {"content": "We decided to approve a launch without an identified speaker."},
        {"role": "user", "content": "We decided to keep the launch paused for review."},
    ]}]
    records = parse_chatgpt(data)
    assert [record.role for record in records] == ["unknown", "user"]
    result = import_records(records, memory, extract_mode=True)
    assert result.messages_seen == 2 and result.imported == 1
    assert "paused" in _stored(memory, result.ids)[0][0]


def test_conversation_time_is_labeled_and_epoch_zero_message_time_preserved(memory):
    data = [{"id": "c", "create_time": 2000, "messages": [
        {"id": "first", "role": "user", "create_time": 0,
         "content": "We decided to keep the original message timestamp."},
        {"id": "second", "role": "user",
         "content": "We decided to label the conversation time fallback."},
    ]}]
    records = parse_chatgpt(data)
    assert [(record.ts, record.source_time_kind) for record in records] == [
        (0, "MESSAGE_TIME"), (2000, "CONVERSATION_TIME")]
    result = import_records(records, memory, extract_mode=True)
    metas = {meta["message_id"]: meta for _, meta in _stored(memory, result.ids)}
    assert metas["first"]["valid_from"] == 0
    assert metas["second"]["source_time_kind"] == "CONVERSATION_TIME"
    assert metas["second"]["source_time_status"] == "CONVERSATION_TIME"


def test_conflicting_stored_key_is_not_reported_as_duplicate(memory):
    text = "We decided to preserve exact source evidence for this candidate."
    ids = extract_and_store(text, memory)
    meta = _stored(memory, ids)[0][1]
    meta["source_binding"]["input_sha256"] = "0" * 64
    memory.store.update_meta(ids[0], meta)
    with pytest.raises(ValueError, match="conflicting text or source binding"):
        extract_and_store(text, memory)
    assert memory.count() == 1
