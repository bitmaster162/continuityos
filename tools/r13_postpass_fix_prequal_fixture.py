from pathlib import Path

p = Path("tests/test_sct_r13_pre_case_qualification.py")
text = p.read_text(encoding="utf-8")

old_import = "from sct.canon import sha256_obj\n"
new_import = "from sct.canon import sha256_obj\nfrom sct.baseline_r13 import baseline_policy_hashes\n"
if text.count(old_import) != 1:
    raise SystemExit(f"import target mismatch: {text.count(old_import)}")
text = text.replace(old_import, new_import, 1)

old = '''        "profile_construction_policy": "Frozen static profile from admitted evidence only.",\n        "profile_builder_sha256": "1" * 64,\n        "retrieval_policy": "Frozen chronological retrieval policy.",\n        "retrieval_policy_sha256": "2" * 64,\n        "source_cutoff_policy": "Same frozen source cutoff as Arm C.",\n        "source_cutoff_sha256": "3" * 64,\n        "admissible_evidence_pool": "Same admitted raw evidence pool as Arm C, without SCT-only claims.",\n        "context_selection_policy": "Deterministic fixed retrieval and truncation policy.",\n        "context_selection_policy_sha256": "4" * 64,\n'''
new = '''        "profile_construction_policy": "Frozen static profile from admitted evidence only.",\n        "retrieval_policy": "Frozen chronological retrieval policy.",\n        "source_cutoff_policy": "Same frozen source cutoff as Arm C.",\n        "admissible_evidence_pool": "Same admitted raw evidence pool as Arm C, without SCT-only claims.",\n        "context_selection_policy": "Deterministic fixed retrieval and truncation policy.",\n        **baseline_policy_hashes(),\n'''
if text.count(old) != 1:
    raise SystemExit(f"baseline fixture target mismatch: {text.count(old)}")
p.write_text(text.replace(old, new, 1), encoding="utf-8")
