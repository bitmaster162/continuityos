# Completion Claim Gate v1

The gate prevents one word such as `done` from collapsing materially different
states. It deliberately uses **independent dimensions**, not one false global
progress ladder.

```text
Work:
DESIGNED → MATERIALIZED → COMMITTED → TESTED_FOCUSED → TESTED_FULL

Artifacts:
NONE → BUNDLE_VERIFIED → FRESH_CLONE_VERIFIED → PACKAGED → READY_LAST_VERIFIED

Git/provider:
UNPUBLISHED → GITHUB_REMOTE_VERIFIED → CI_VERIFIED

Delivery flags:
USER_DOWNLOAD_EXPOSED
DRIVE_READBACK_VERIFIED

Semantic:
ACCEPTED
```

This prevents invalid implications:

```text
GitHub remote verification does not require Google Drive.
Google Drive readback does not imply GitHub or CI.
A ZIP does not imply user exposure.
A bundle does not imply fresh-clone tests.
CI success does not imply semantic acceptance.
```

The evaluator reports the maximum proven state on each axis and lists every
unsupported claim. It is verify-only and cannot write Git, publish, merge,
deploy, apply R63/current state/registry, access wallets, execute orders or
trade.
