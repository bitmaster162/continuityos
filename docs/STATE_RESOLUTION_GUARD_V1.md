# State Resolution Guard v1

Purpose: prevent stale or lower-authority evidence from rolling current truth backward.

The concrete regression this closes is: an old `OPEN` receipt template remains on Drive,
while a later byte audit and human operational closure decision already exist. A naive
"find OPEN" scan incorrectly reopens completed remediation work.

Precedence:

`TEMPLATE < REMEDIATION_RETURN < AUDIT < PROVIDER_READBACK < CONTROLLER_ADJUDICATION < HUMAN_DECISION`

Within one authority class, newer evidence wins. Equal-authority/equal-time conflicting
states fail closed. A fresh current AUDIT/PROVIDER_READBACK can block reliance on an older
accepted decision if it reports `OPEN`, `REVISE`, or `REJECT`; it blocks but does not gain
higher authority.

`PASS_WITH_CONDITIONS` is operational acceptance, not production-qualified security.
Production-qualified output requires exact `PASS`, `production_qualified=true`, and no
evidence debt.

The resolver is pure/read-only and cannot mutate Git, Drive, current state, registries,
deployments, trading, wallets, capital permissions, or messages.
