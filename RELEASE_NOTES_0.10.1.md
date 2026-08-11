# ContinuityOS 0.10.1 — Release Preparation Notes

Status: **release-prep candidate; not tagged or published**.

This candidate gives the post-0.10.0 productization changes a new package identity instead of reusing the existing `0.10.0` version after additional code landed on the integration branch.

## What changed after the 0.10.0 release-candidate baseline

### Offline-first `cos boot`

`cos boot` now follows the product router and remains local/offline by default:

- opens the existing local memory through `Memory(db)` without initializing FastEmbed/model providers;
- does not invoke the updater on the default boot path;
- exposes `cos boot --check-updates` as the explicit PyPI network opt-in;
- holds on a missing memory DB before attempting an update check;
- preserves verified R64 current-session containment before product boot loads.

### Offline-first core CLI embedder policy

Ordinary core `cos` commands now default to the dependency-free local Hashing embedder path instead of opportunistically constructing FastEmbed when it happens to be installed.

Policy:

- default/offline aliases: empty, `hash`, `hashing`, `offline`, `local`;
- explicit FastEmbed opt-in: `CONTINUITYOS_EMBEDDER=fast` or `fastembed`;
- unsupported embedder modes fail closed with `COS_EMBEDDER_POLICY_HOLD` before DB open/write;
- verified R64 containment takes precedence over embedder selection;
- routed `connect`, `status`, `demo`, and `boot` behavior remains unchanged.

## Version identity

Canonical package version for this candidate:

```text
0.10.1
```

`cos --version` and package metadata derive from the same canonical `continuityos._version.__version__` value.

## Compatibility

- Python 3.10+
- stdlib-only core remains supported
- optional embedding extras remain opt-in
- canonical `cos = continuityos.current_entrypoints:cos_main` entrypoint remains unchanged

## Release boundary

This release-prep candidate does **not** authorize or perform:

- creation of tag `v0.10.1`;
- GitHub Release publication;
- PyPI publication;
- deployment;
- OperationalMemory/R64/current-state mutation;
- agent dispatch;
- trading, wallet, or capital effects.

Tagging and publication remain separate explicit operator-authorized effects after release-prep review and merge.
