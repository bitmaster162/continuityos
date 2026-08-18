# SCT R13 R1 — immutable PASS receipt

Scientific source:
- SHA `2b3f0288ee35eb8d6554218694f9111e29147dd2`
- tree `174c5045af3e43b1be62dfc07335de0ea6ea095e`

Existing scientific calls:
- determinism preflight: `2/2 PASS`
- balanced context sentinel: `18/18 PASS`
- stable VOID: `30/30 PASS`
- total existing model/logit calls: `50`
- scientific calls re-executed during offline adjudication: `0`

Qualification:
- `scientific_pre_case_gate_pass=true`
- qualification SHA-256 `fe64f44570486e9971d451776085c64ac742a0b490f9c43a4d4af73084d02af2`
- terminal failure recorded: `false`
- `valid_live_n=0`
- Case #001 authorized: `false`
- LIVE enrollment allowed: `false`
- `can_execute=false`
- `execution_authority=NONE`

The first qualification command rejected the CLI wrapper JSON because `attempt_lifecycle` was added after the scientific core receipt had been hashed into the EvidenceStore. Offline adjudication removed only that late wrapper and proved the resulting core hashes exactly matched the immutable component receipts already recorded in the original R13 EvidenceStore. No scientific component or model call was rerun.

Case #001 remains blocked pending LIVE Arm B provenance hardening and separate exact owner authorization.
