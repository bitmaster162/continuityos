import pytest

from sct.baseline_r13 import (
    admitted_pool_sha256,
    admitted_segments,
    baseline_policy_hashes,
    build_arm_b_profile_rag,
)
from sct.errors import EvidenceError
from sct.r13 import R13_BASELINE_SCHEMA
from sct.r13_manifest_guard import validate_baseline_for_seal
from sct.runner.hf_local import verify_alias_tokens


class FakeTokenizer:
    def __init__(self, mapping):
        self.mapping = dict(mapping)
        self.reverse = {v: k for k, v in self.mapping.items()}

    def encode(self, text, add_special_tokens=False):
        if text == "Selected option: ":
            return [900, 901]
        if text in self.mapping:
            return [self.mapping[text]]
        return [999, 998]

    def decode(self, ids, skip_special_tokens=False, clean_up_tokenization_spaces=False):
        if ids == [900, 901]:
            return "Selected option: "
        if len(ids) == 1 and ids[0] in self.reverse:
            return self.reverse[ids[0]]
        if len(ids) == 3 and ids[:2] == [900, 901] and ids[2] in self.reverse:
            return "Selected option: " + self.reverse[ids[2]]
        return "?"


def _manifest_aliases():
    return {"alias_tokens": [{"alias": chr(65 + i), "token_id": 32 + i} for i in range(15)]}


def _rows():
    return [
        {
            "segment_id": "profile-1",
            "source_id": "chatgpt-raw",
            "text": "I prefer reversible experiments and explicit evidence gates.",
            "observed_at": 100.0,
            "profile_eligible": True,
            "admitted": True,
            "assistant_authored": False,
            "sct_only_derived": False,
            "authorship": "HUMAN_USER",
        },
        {
            "segment_id": "history-1",
            "source_id": "chatgpt-raw",
            "text": "For deployment decisions I compare rollback cost and evidence quality.",
            "observed_at": 110.0,
            "profile_eligible": False,
            "admitted": True,
            "assistant_authored": False,
            "sct_only_derived": False,
            "authorship": "HUMAN_USER",
        },
        {
            "segment_id": "assistant-echo",
            "source_id": "chatgpt-raw",
            "text": "The assistant says reversible experiments are preferred.",
            "observed_at": 120.0,
            "profile_eligible": True,
            "admitted": True,
            "assistant_authored": True,
            "sct_only_derived": False,
            "authorship": "HUMAN_USER",
        },
        {
            "segment_id": "sct-derived",
            "source_id": "projection",
            "text": "SCT structured claim about reversible experiments.",
            "observed_at": 115.0,
            "profile_eligible": True,
            "admitted": True,
            "assistant_authored": False,
            "sct_only_derived": True,
            "authorship": "HUMAN_USER",
        },
        {
            "segment_id": "future",
            "source_id": "chatgpt-raw",
            "text": "Future information must not enter the baseline.",
            "observed_at": 1000.0,
            "profile_eligible": True,
            "admitted": True,
            "assistant_authored": False,
            "sct_only_derived": False,
            "authorship": "HUMAN_USER",
        },
    ]


def test_hf_alias_verifier_requires_exact_one_token_and_prefix_reconstruction():
    tokenizer = FakeTokenizer({chr(65 + i): 32 + i for i in range(15)})
    out = verify_alias_tokens(tokenizer, _manifest_aliases())
    assert out["A"] == 32
    assert out["O"] == 46
    assert len(out) == 15


def test_hf_alias_verifier_rejects_manifest_token_id_drift():
    tokenizer = FakeTokenizer({chr(65 + i): 32 + i for i in range(15)})
    manifest = _manifest_aliases()
    manifest["alias_tokens"][0]["token_id"] = 999
    with pytest.raises(EvidenceError, match="one-token encoding"):
        verify_alias_tokens(tokenizer, manifest)


def test_arm_b_builder_is_deterministic_cutoff_bound_and_contamination_free():
    admitted = admitted_segments(_rows(), source_cutoff=200.0)
    assert {s.segment_id for s in admitted} == {"profile-1", "history-1"}
    pool_sha = admitted_pool_sha256(admitted)
    kwargs = dict(
        scenario="Should I deploy now or wait for more evidence?",
        options=("deploy", "wait"),
        evidence_rows=_rows(),
        source_cutoff=200.0,
        target_context_bytes=512,
        expected_admitted_pool_sha256=pool_sha,
    )
    a = build_arm_b_profile_rag(**kwargs)
    b = build_arm_b_profile_rag(**kwargs)
    assert a == b
    combined = a["static_profile"] + "\n" + a["permitted_history"]
    assert "profile-1" in combined
    assert "history-1" in combined
    assert "assistant-echo" not in combined
    assert "sct-derived" not in combined
    assert "future" not in combined
    assert a["assistant_authored_admitted"] is False
    assert a["sct_only_derived_admitted"] is False
    assert a["payload_bytes"] <= a["target_context_bytes"]
    assert a["policy_hashes"] == baseline_policy_hashes()


def test_arm_b_builder_fails_closed_on_admitted_pool_mismatch():
    with pytest.raises(EvidenceError, match="pool SHA-256 mismatch"):
        build_arm_b_profile_rag(
            scenario="A or B?",
            options=("A", "B"),
            evidence_rows=_rows(),
            source_cutoff=200.0,
            target_context_bytes=512,
            expected_admitted_pool_sha256="0" * 64,
        )


def test_baseline_seal_must_match_exact_builder_policy_hashes():
    spec = {
        "schema": R13_BASELINE_SCHEMA,
        "profile_construction_policy": "Deterministic human-authored profile-eligible excerpts from the same admitted raw pool.",
        "retrieval_policy": "Deterministic Unicode lexical overlap retrieval from the same admitted raw pool.",
        "source_cutoff_policy": "Only observed_at <= frozen source cutoff; no future evidence.",
        "admissible_evidence_pool": "Same raw admitted pool as Arm C; assistant-authored and SCT-only derived evidence forbidden.",
        "context_selection_policy": "40% initial profile / 60% retrieval with deterministic spill and 1.15 payload-parity ceiling.",
        "disallow_sct_structured_claims": True,
        "payload_parity_ratio": 1.15,
        "execution_authority": "NONE",
        **baseline_policy_hashes(),
    }
    validated = validate_baseline_for_seal(spec)
    assert validated["profile_builder_sha256"] == baseline_policy_hashes()["profile_builder_sha256"]
    bad = dict(spec)
    bad["retrieval_policy_sha256"] = "f" * 64
    with pytest.raises(EvidenceError, match="does not match frozen implementation policy"):
        validate_baseline_for_seal(bad)
