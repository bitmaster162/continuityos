import base64
import copy
import hashlib
import json

import pytest

from continuityos.governed_delivery_pipeline import (
    build_code_receipt,
    build_human_merge_gate_request,
    build_plan_receipt,
    build_review_receipt,
    build_test_receipt,
)
from continuityos.trusted_human_approval import (
    ALGORITHM,
    APPROVAL_SCHEMA,
    ELIGIBILITY_SCHEMA,
    PURPOSE,
    REGISTRY_SCHEMA,
    InMemoryApprovalReplayGuard,
    approval_signing_message,
    require_merge_eligibility_current,
    verify_and_consume_human_approval,
)

BASE = "a" * 40
BASE_TREE = "b" * 40
HEAD = "c" * 40
TREE = "d" * 40
REPOSITORY = "bitmaster162/continuityos"
NOW = 2_000_000_000


def actor(role, sid):
    return {
        "provider": "test-provider",
        "declared_model_id": f"test-{role}",
        "attested_runtime_model_id": f"test-{role}",
        "session_id": sid,
        "route_id": f"route-{role}",
    }


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def request(parity_mode="PRESERVE"):
    delta = None if parity_mode == "PRESERVE" else sha("delta")
    plan = build_plan_receipt(
        work_order_id="wo-r17",
        generation=1,
        repository=REPOSITORY,
        baseline_sha=BASE,
        baseline_tree_sha=BASE_TREE,
        scope_sha256=sha("scope"),
        acceptance_sha256=sha("acceptance"),
        parity_spec_sha256=sha("parity"),
        parity_mode=parity_mode,
        expected_delta_sha256=delta,
        effect_ceiling="EVIDENCE_ONLY",
        actor=actor("planner", "s-plan"),
        attempt_nonce="n-plan",
    )
    code = build_code_receipt(
        plan,
        candidate_sha=HEAD,
        candidate_tree_sha=TREE,
        diff_sha256=sha("diff"),
        actor=actor("coder", "s-code"),
        attempt_nonce="n-code",
    )
    tested = build_test_receipt(
        code,
        tests_passed=True,
        test_suite_sha256=sha("suite"),
        parity_result="PARITY_PASS" if parity_mode == "PRESERVE" else "EXPECTED_DELTA_PASS",
        parity_result_sha256=sha("parity-result"),
        observed_delta_sha256=delta,
        actor=actor("tester", "s-test"),
        attempt_nonce="n-test",
    )
    reviewed = build_review_receipt(
        tested,
        verdict="PASS",
        review_sha256=sha("review"),
        actor=actor("reviewer", "s-review"),
        attempt_nonce="n-review",
    )
    return build_human_merge_gate_request(
        reviewed,
        current_base_sha=BASE,
        current_head_sha=HEAD,
        current_tree_sha=TREE,
        attempt_nonce="n-human-request",
    )


def key_material():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_b64u = base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii")
    registry = {
        "schema": REGISTRY_SCHEMA,
        "keys": [{
            "signer_id": "operator-robert",
            "key_id": "operator-key-r1",
            "algorithm": ALGORITHM,
            "public_key_b64u": public_b64u,
            "active": True,
        }],
    }
    pin = hashlib.sha256(json.dumps(registry, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    return private, registry, pin


def signed_envelope(req, private, *, issued=NOW - 5, expires=NOW + 300, nonce="1" * 64, mutate=None):
    payload = {
        "schema": APPROVAL_SCHEMA,
        "purpose": PURPOSE,
        "algorithm": ALGORITHM,
        "signer_id": "operator-robert",
        "key_id": "operator-key-r1",
        "request_receipt_id": req["receipt_id"],
        "repository": req["repository"],
        "work_order_id": req["work_order_id"],
        "generation": req["generation"],
        "policy_version": req["policy_version"],
        "baseline_sha": req["baseline_sha"],
        "candidate_sha": req["candidate_sha"],
        "candidate_tree_sha": req["candidate_tree_sha"],
        "parity_mode": req["parity_mode"],
        "expected_delta_sha256": req["expected_delta_sha256"],
        "observed_delta_sha256": req["observed_delta_sha256"],
        "approve_expected_delta": req["parity_mode"] == "INTENTIONAL_CHANGE",
        "decision": "APPROVE",
        "issued_at_unix": issued,
        "expires_at_unix": expires,
        "approval_nonce": nonce,
    }
    if mutate:
        mutate(payload)
    signature = private.sign(approval_signing_message(payload))
    return {**payload, "signature_b64u": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")}


def approve(req=None, *, parity_mode="PRESERVE"):
    req = req or request(parity_mode)
    private, registry, pin = key_material()
    envelope = signed_envelope(req, private)
    replay_guard = InMemoryApprovalReplayGuard()
    result = verify_and_consume_human_approval(
        request_receipt=req,
        approval_envelope=envelope,
        trusted_key_registry=registry,
        pinned_registry_sha256=pin,
        repository=REPOSITORY,
        current_base_sha=BASE,
        current_head_sha=HEAD,
        current_tree_sha=TREE,
        now_unix=NOW,
        replay_guard=replay_guard,
    )
    return req, envelope, registry, pin, replay_guard, result


def test_preserve_approval_yields_exact_merge_eligibility_only():
    req, envelope, registry, pin, replay_guard, result = approve()
    receipt = result.eligibility_receipt
    assert receipt["schema"] == ELIGIBILITY_SCHEMA
    assert receipt["status"] == "MERGE_ELIGIBLE"
    assert receipt["can_merge"] is True
    assert receipt["merge_authority"] == "HUMAN_APPROVED_EXACT_CANDIDATE"
    assert receipt["can_execute"] is False
    assert receipt["deploy_permission"] == "DENY"
    assert receipt["can_trade"] is False
    assert receipt["capital_permission"] == "DENY"
    assert receipt["authenticated_human_approval_present"] is True
    assert receipt["human_delta_approved"] is False
    assert replay_guard.contains(result.approval_id)
    assert require_merge_eligibility_current(
        receipt,
        trusted_key_registry=registry,
        pinned_registry_sha256=pin,
        repository=REPOSITORY,
        current_base_sha=BASE,
        current_head_sha=HEAD,
        current_tree_sha=TREE,
        now_unix=NOW,
    )["receipt_id"] == receipt["receipt_id"]


def test_intentional_change_requires_explicit_signed_delta_approval():
    req = request("INTENTIONAL_CHANGE")
    private, registry, pin = key_material()
    bad = signed_envelope(req, private, mutate=lambda p: p.__setitem__("approve_expected_delta", False))
    with pytest.raises(ValueError, match="explicit delta approval mismatch"):
        verify_and_consume_human_approval(
            request_receipt=req, approval_envelope=bad, trusted_key_registry=registry,
            pinned_registry_sha256=pin, repository=REPOSITORY, current_base_sha=BASE, current_head_sha=HEAD,
            current_tree_sha=TREE, now_unix=NOW, replay_guard=InMemoryApprovalReplayGuard(),
        )
    good = signed_envelope(req, private)
    result = verify_and_consume_human_approval(
        request_receipt=req, approval_envelope=good, trusted_key_registry=registry,
        pinned_registry_sha256=pin, repository=REPOSITORY, current_base_sha=BASE, current_head_sha=HEAD,
        current_tree_sha=TREE, now_unix=NOW, replay_guard=InMemoryApprovalReplayGuard(),
    )
    assert result.eligibility_receipt["human_delta_approved"] is True


def test_bad_signature_and_registry_pin_fail_closed():
    req = request()
    private, registry, pin = key_material()
    env = signed_envelope(req, private)
    bad_sig = copy.deepcopy(env)
    bad_sig["signature_b64u"] = ("A" if env["signature_b64u"][0] != "A" else "B") + env["signature_b64u"][1:]
    with pytest.raises(ValueError, match="signature invalid"):
        verify_and_consume_human_approval(
            request_receipt=req, approval_envelope=bad_sig, trusted_key_registry=registry,
            pinned_registry_sha256=pin, repository=REPOSITORY, current_base_sha=BASE, current_head_sha=HEAD,
            current_tree_sha=TREE, now_unix=NOW, replay_guard=InMemoryApprovalReplayGuard(),
        )
    with pytest.raises(ValueError, match="registry pin mismatch"):
        verify_and_consume_human_approval(
            request_receipt=req, approval_envelope=env, trusted_key_registry=registry,
            pinned_registry_sha256="0" * 64, repository=REPOSITORY, current_base_sha=BASE, current_head_sha=HEAD,
            current_tree_sha=TREE, now_unix=NOW, replay_guard=InMemoryApprovalReplayGuard(),
        )


def test_signed_candidate_binding_mismatch_rejected():
    req = request()
    private, registry, pin = key_material()
    env = signed_envelope(req, private, mutate=lambda p: p.__setitem__("candidate_sha", "e" * 40))
    with pytest.raises(ValueError, match="binding mismatch for candidate_sha"):
        verify_and_consume_human_approval(
            request_receipt=req, approval_envelope=env, trusted_key_registry=registry,
            pinned_registry_sha256=pin, repository=REPOSITORY, current_base_sha=BASE, current_head_sha=HEAD,
            current_tree_sha=TREE, now_unix=NOW, replay_guard=InMemoryApprovalReplayGuard(),
        )


def test_expired_future_and_excessive_ttl_rejected():
    req = request()
    private, registry, pin = key_material()
    cases = [
        (signed_envelope(req, private, issued=NOW - 100, expires=NOW - 1), "approval expired"),
        (signed_envelope(req, private, issued=NOW + 61, expires=NOW + 120), "issued in future"),
        (signed_envelope(req, private, issued=NOW, expires=NOW + 901), "TTL exceeds policy"),
    ]
    for env, pattern in cases:
        with pytest.raises(ValueError, match=pattern):
            verify_and_consume_human_approval(
                request_receipt=req, approval_envelope=env, trusted_key_registry=registry,
                pinned_registry_sha256=pin, repository=REPOSITORY, current_base_sha=BASE, current_head_sha=HEAD,
                current_tree_sha=TREE, now_unix=NOW, replay_guard=InMemoryApprovalReplayGuard(),
            )


def test_replay_is_rejected_by_explicit_consumption_guard():
    req = request()
    private, registry, pin = key_material()
    env = signed_envelope(req, private)
    replay_guard = InMemoryApprovalReplayGuard()
    kwargs = dict(
        request_receipt=req, approval_envelope=env, trusted_key_registry=registry,
        pinned_registry_sha256=pin, repository=REPOSITORY, current_base_sha=BASE, current_head_sha=HEAD,
        current_tree_sha=TREE, now_unix=NOW, replay_guard=replay_guard,
    )
    verify_and_consume_human_approval(**kwargs)
    with pytest.raises(ValueError, match="approval replay detected"):
        verify_and_consume_human_approval(**kwargs)


def test_request_revision_drift_rejected_before_signature_authority():
    req = request()
    private, registry, pin = key_material()
    env = signed_envelope(req, private)
    with pytest.raises(ValueError, match="candidate drift after Human gate request"):
        verify_and_consume_human_approval(
            request_receipt=req, approval_envelope=env, trusted_key_registry=registry,
            pinned_registry_sha256=pin, repository=REPOSITORY, current_base_sha=BASE, current_head_sha="e" * 40,
            current_tree_sha=TREE, now_unix=NOW, replay_guard=InMemoryApprovalReplayGuard(),
        )


def test_resealed_eligibility_cannot_escape_signed_envelope():
    req, envelope, registry, pin, replay_guard, result = approve()
    forged = copy.deepcopy(result.eligibility_receipt)
    forged["candidate_sha"] = "e" * 40
    unsigned = {k: v for k, v in forged.items() if k != "receipt_id"}
    forged["receipt_id"] = "hme_" + hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    with pytest.raises(ValueError, match="candidate drift after Human gate request"):
        require_merge_eligibility_current(
            forged, trusted_key_registry=registry, pinned_registry_sha256=pin, repository=REPOSITORY,
            current_base_sha=BASE, current_head_sha="e" * 40, current_tree_sha=TREE, now_unix=NOW,
        )


def test_eligibility_expiry_and_revision_drift_fail_closed():
    req, envelope, registry, pin, replay_guard, result = approve()
    receipt = result.eligibility_receipt
    with pytest.raises(ValueError, match="candidate drift after Human gate request"):
        require_merge_eligibility_current(
            receipt, trusted_key_registry=registry, pinned_registry_sha256=pin, repository=REPOSITORY,
            current_base_sha=BASE, current_head_sha="e" * 40, current_tree_sha=TREE, now_unix=NOW,
        )
    with pytest.raises(ValueError, match="merge eligibility expired"):
        require_merge_eligibility_current(
            receipt, trusted_key_registry=registry, pinned_registry_sha256=pin, repository=REPOSITORY,
            current_base_sha=BASE, current_head_sha=HEAD, current_tree_sha=TREE, now_unix=NOW + 301,
        )


def test_module_has_no_private_key_signer_or_merge_execution_surface():
    import ast
    from pathlib import Path
    source = Path("continuityos/trusted_human_approval.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    banned = {"subprocess", "socket", "requests", "urllib", "github", "git"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not (banned & imported)
    assert "Ed25519PrivateKey" not in source
    assert "merge_pull_request" not in source
    assert "can_merge\": True" in source


def test_repository_is_signed_and_current_repository_is_revalidated():
    req = request()
    private, registry, pin = key_material()
    wrong_signed = signed_envelope(req, private, mutate=lambda p: p.__setitem__("repository", "other/repo"))
    with pytest.raises(ValueError, match="binding mismatch for repository"):
        verify_and_consume_human_approval(
            request_receipt=req, approval_envelope=wrong_signed, trusted_key_registry=registry,
            pinned_registry_sha256=pin, repository=REPOSITORY, current_base_sha=BASE,
            current_head_sha=HEAD, current_tree_sha=TREE, now_unix=NOW,
            replay_guard=InMemoryApprovalReplayGuard(),
        )
    env = signed_envelope(req, private)
    with pytest.raises(ValueError, match="repository mismatch"):
        verify_and_consume_human_approval(
            request_receipt=req, approval_envelope=env, trusted_key_registry=registry,
            pinned_registry_sha256=pin, repository="other/repo", current_base_sha=BASE,
            current_head_sha=HEAD, current_tree_sha=TREE, now_unix=NOW,
            replay_guard=InMemoryApprovalReplayGuard(),
        )


def test_registry_is_bounded_and_key_contract_is_exact():
    req = request()
    private, registry, pin = key_material()
    env = signed_envelope(req, private)
    oversized = copy.deepcopy(registry)
    oversized["keys"] = oversized["keys"] * 33
    oversized_pin = hashlib.sha256(json.dumps(oversized, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    with pytest.raises(ValueError, match="registry too large"):
        verify_and_consume_human_approval(
            request_receipt=req, approval_envelope=env, trusted_key_registry=oversized,
            pinned_registry_sha256=oversized_pin, repository=REPOSITORY, current_base_sha=BASE,
            current_head_sha=HEAD, current_tree_sha=TREE, now_unix=NOW,
            replay_guard=InMemoryApprovalReplayGuard(),
        )
    inactive = copy.deepcopy(registry)
    inactive["keys"][0]["active"] = False
    inactive_pin = hashlib.sha256(json.dumps(inactive, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    with pytest.raises(ValueError, match="trusted key inactive"):
        verify_and_consume_human_approval(
            request_receipt=req, approval_envelope=env, trusted_key_registry=inactive,
            pinned_registry_sha256=inactive_pin, repository=REPOSITORY, current_base_sha=BASE,
            current_head_sha=HEAD, current_tree_sha=TREE, now_unix=NOW,
            replay_guard=InMemoryApprovalReplayGuard(),
        )


def test_final_handoff_revalidates_nested_r16_request_not_just_outer_hash():
    req, envelope, registry, pin, replay_guard, result = approve()
    forged = copy.deepcopy(result.eligibility_receipt)
    forged["request_receipt"]["candidate_tree_sha"] = "e" * 40
    # Reseal outer receipt to prove the inner R16 receipt still fails closed.
    unsigned = {k: v for k, v in forged.items() if k != "receipt_id"}
    forged["receipt_id"] = "hme_" + hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    with pytest.raises(ValueError, match="receipt integrity mismatch"):
        require_merge_eligibility_current(
            forged, trusted_key_registry=registry, pinned_registry_sha256=pin, repository=REPOSITORY,
            current_base_sha=BASE, current_head_sha=HEAD, current_tree_sha=TREE, now_unix=NOW,
        )
