import json

from sct.r13 import R13_ADAPTER_ID, R13_CHOICE_PREFIX, render_r13_logit_request
from sct.runner.hf_local import render_model_visible_prompt


class FakeChatTokenizer:
    def __init__(self):
        self.kwargs = None
        self.messages = None

    def apply_chat_template(self, messages, **kwargs):
        self.messages = messages
        self.kwargs = kwargs
        assert messages[-1]["role"] == "user"
        return "<system>shadow</system><user>payload</user><assistant>"


def test_r13_v2_request_uses_exact_final_assistant_prefill():
    request = render_r13_logit_request(
        scenario="Synthetic prefill test",
        semantic_options=("X", "Y"),
        personal_context="SYNTHETIC QUALIFICATION ONLY",
        semantic_to_alias={"X": "A", "Y": "B"},
        textual_order=("X", "Y"),
        provider="p",
        model="m",
        model_version="v",
    )
    assert R13_ADAPTER_ID == "sct.r13-direct-constrained-label-logits/v2"
    assert request["messages"][-1] == {"role": "assistant", "content": R13_CHOICE_PREFIX}
    payload = json.loads(request["messages"][-2]["content"])
    assert payload["scenario"] == "Synthetic prefill test"
    assert not request["messages"][-2]["content"].endswith(R13_CHOICE_PREFIX)


def test_hf_renderer_opens_assistant_turn_then_appends_exact_literal_prefix():
    tokenizer = FakeChatTokenizer()
    messages = [
        {"role": "system", "content": "shadow"},
        {"role": "user", "content": "payload"},
        {"role": "assistant", "content": R13_CHOICE_PREFIX},
    ]
    rendered = render_model_visible_prompt(tokenizer, messages)
    assert rendered.endswith(R13_CHOICE_PREFIX)
    assert tokenizer.messages == messages[:-1]
    assert tokenizer.kwargs == {"tokenize": False, "add_generation_prompt": True}
