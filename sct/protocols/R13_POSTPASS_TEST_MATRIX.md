# Post-PASS adversarial test matrix

Receipt-wrapper:
- exact emitted wrapper -> normalize to recorded core -> PASS
- scientific field changed -> FAIL
- lifecycle receipt hash changed -> FAIL
- extra unknown wrapper field -> FAIL

LIVE Arm B provenance:
- frozen builder output + exact pool/cutoff/policy/payload hashes -> admissible after owner gate
- arbitrary static profile -> FAIL
- arbitrary permitted history -> FAIL
- wrong admitted pool hash -> FAIL
- post-cutoff evidence -> FAIL
- assistant-authored evidence -> FAIL
- SCT-derived evidence -> FAIL
- tampered policy hash -> FAIL
- direct ProspectiveArena.open_case bypass -> FAIL
- direct SQLiteEvidenceStore CASE_FROZEN append bypass -> FAIL

All tests are mock/fixture only. No R13 model call is allowed.
