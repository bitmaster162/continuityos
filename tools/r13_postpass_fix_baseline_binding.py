from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one patch target, got {count}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# The append-only sealed baseline event carries the manifest hash, not a duplicate of every policy hash.
# Validate provenance policy hashes against the current frozen builder, and bind the receipt to the sealed
# baseline through its manifest SHA. Future direct Python seals are hardened below.
replace_once(
    "sct/r13_live_provenance.py",
    '''    expected_policy = baseline_policy_hashes()\n    if receipt.get("policy_hashes") != expected_policy:\n        raise EvidenceError("R13 Arm B LIVE provenance policy hash mismatch")\n    for field, expected in expected_policy.items():\n        if sealed_baseline.get(field) != expected:\n            raise EvidenceError(f"R13 Arm B LIVE provenance sealed baseline policy mismatch: {field}")\n''',
    '''    expected_policy = baseline_policy_hashes()\n    if receipt.get("policy_hashes") != expected_policy:\n        raise EvidenceError("R13 Arm B LIVE provenance policy hash mismatch")\n    if sealed_baseline.get("execution_authority") != "NONE" or sealed_baseline.get("can_execute") is not False:\n        raise EvidenceError("R13 Arm B LIVE provenance sealed baseline governance mismatch")\n''',
)

# Remove the harmless/raw-vs-canonical no-op left in the initial verifier draft.
replace_once(
    "sct/r13_live_provenance.py",
    '''    blob_sha = _sha256(receipt.get("evidence_blob_sha256"), "evidence_blob_sha256")\n    if sha256_obj(evidence_blob.decode("utf-8")) == blob_sha:\n        # sha256_obj hashes canonical JSON strings, while EvidenceStore blob IDs hash raw bytes.\n        # This branch is deliberately not used as the blob identity check below.\n        pass\n    import hashlib\n''',
    '''    blob_sha = _sha256(receipt.get("evidence_blob_sha256"), "evidence_blob_sha256")\n    import hashlib\n''',
)

# Direct Python seal must enforce the same frozen builder-policy hashes as the CLI seal path.
replace_once(
    "sct/r13.py",
    '''def seal_baseline_spec(store, spec: Mapping[str, Any], *, protocol_manifest_sha256: str) -> dict[str, Any]:\n    validated = validate_baseline_spec(spec)\n''',
    '''def seal_baseline_spec(store, spec: Mapping[str, Any], *, protocol_manifest_sha256: str) -> dict[str, Any]:\n    from .r13_manifest_guard import validate_baseline_for_seal\n    validated = validate_baseline_for_seal(spec)\n''',
)

# Terminal-attempt fixtures now use the real frozen builder policy hashes.
replace_once(
    "tests/test_sct_r13_terminal_attempt.py",
    "from sct.canon import sha256_obj\n",
    "from sct.canon import sha256_obj\nfrom sct.baseline_r13 import baseline_policy_hashes\n",
)
replace_once(
    "tests/test_sct_r13_terminal_attempt.py",
    '''        "profile_builder_sha256": "1" * 64,\n        "retrieval_policy": "Frozen retrieval.",\n        "retrieval_policy_sha256": "2" * 64,\n        "source_cutoff_policy": "Frozen cutoff.",\n        "source_cutoff_sha256": "3" * 64,\n        "admissible_evidence_pool": "Frozen admitted pool.",\n        "context_selection_policy": "Frozen deterministic selection.",\n        "context_selection_policy_sha256": "4" * 64,''',
    '''        "retrieval_policy": "Frozen retrieval.",\n        "source_cutoff_policy": "Frozen cutoff.",\n        "admissible_evidence_pool": "Frozen admitted pool.",\n        "context_selection_policy": "Frozen deterministic selection.",\n        **baseline_policy_hashes(),''',
)
