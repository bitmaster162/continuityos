from __future__ import annotations

import continuityos.sovereign_twin_api as api


def test_r15_ui_keeps_all_three_answer_modes_and_dedicated_deep_lite_endpoint():
    text = api._UI
    assert ">FAST<" in text
    assert ">DEEP<" in text
    assert ">DEEP-LITE<" in text
    assert "postAsk('/ask',{query:q,mode}" in text
    assert "postAsk('/ask/deep-lite',{query:q},'DEEP-LITE')" in text


def test_r15_ui_renders_human_answer_before_raw_payload():
    text = api._UI
    assert 'id="answer"' in text
    assert 'id="raw"' in text
    assert "answer.textContent=" in text
    assert "raw.textContent=JSON.stringify(payload,null,2)" in text
    assert text.index('id="answer"') < text.index('id="raw"')


def test_r15_ui_renders_evidence_with_dom_text_content_not_inner_html():
    text = api._UI
    assert 'id="evidence"' in text
    assert "document.createElement('li')" in text
    assert "id.textContent=evidenceLabel(item)" in text
    assert "body.textContent=" in text
    assert ".innerHTML" not in text


def test_r15_ui_surfaces_shadow_authority_and_answer_metadata():
    text = api._UI
    assert "LOCAL_SHADOW" in text
    assert "AUTHORITY NONE" in text
    assert "payload.model" in text
    assert "payload.stats.pass_count" in text
    assert "payload.execution_authority" in text


def test_r15_ui_has_fail_closed_client_error_handling():
    text = api._UI
    assert "Query required." in text
    assert "if(!response.ok||data.ok===false||data.error)" in text
    assert "status.textContent='Error: '" in text
    assert "buttons().forEach(b=>b.disabled=busy)" in text


def test_r15_is_presentation_only_and_does_not_add_browser_mutation_routes():
    text = api._UI
    assert "fetch('/admissions'" not in text
    assert "fetch('/doctor'" not in text
    assert "fetch('/health'" not in text
    assert "method:'POST'" in text
    assert text.count("postAsk('/ask") == 2
