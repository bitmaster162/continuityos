# ContinuityOS 0.10.2 — Release Preparation Notes

Status: **release-prep candidate; not tagged or published**.

This patch release carries the post-0.10.1 public-product convergence and `cos setup` hardening into a new package identity instead of modifying or reusing the already-published `0.10.1` artifact.

## What changed after 0.10.1

### Product-first public onboarding

The default GitHub README now leads with the supported product path instead of the historical governance-first surface:

```text
pip install continuityos
cos setup
cos import <export-path> --extract
cos status
cos connect <client>
cos demo continuity
cos boot
```

The README keeps governance/security caveats below that product path and continues to state that controlled enforcement applies only to explicitly routed surfaces.

### `cos setup` offline-policy hardening

`cos setup` now follows the same offline-first embedder policy as the packaged core CLI:

- local deterministic `HashingEmbedder` remains the default even when optional FastEmbed support is installed;
- FastEmbed construction requires explicit `CONTINUITYOS_EMBEDDER=fast` or `fastembed` opt-in;
- unsupported embedder modes fail closed with `COS_EMBEDDER_POLICY_HOLD` before legacy CLI/setup filesystem/database effects;
- verified R64/current-session containment continues to take precedence over product setup;
- setup no longer writes provider secrets or an onboarding `.env` file.

### Setup product-surface cleanup

The guided setup flow was narrowed to the documented durable-memory/continuity product contract. Historical internal onboarding claims and references were removed, including stale Hermes/OpenRouter/Nemotron/Antigravity/monetization/`Trade/HANDOFF` guidance and the hard-coded `Asia/Bangkok` default.

Compatibility-only setup surfaces retained by the hardening include `cos setup --quick`, `cos setup --dashboard-only`, and the existing `ENV_FILE` module symbol required by older containment callers/tests; retaining that symbol does not restore secret-writing behavior.

### Dedicated regression coverage

A product-specific setup regression suite now covers:

- default local/offline embedder selection;
- explicit FastEmbed opt-in;
- unknown embedder mode fail-closed behavior;
- HOLD before legacy CLI invocation/effects;
- removal of stale setup product-surface claims.

The existing review-gates matrix still validates clean-source, wheel-only, editable-install, compile, governance corpus, portable release-hardening, and mandatory Linux realpath behavior before merge.

## Version identity

Canonical package version for this candidate:

```text
0.10.2
```

`cos --version` and package metadata derive from the same canonical `continuityos._version.__version__` value.

## Compatibility

- Python 3.10+
- stdlib-only core remains supported
- optional embedding extras remain opt-in
- canonical `cos = continuityos.current_entrypoints:cos_main` entrypoint remains unchanged

## Known repository hardening gap

Default-branch protection/rulesets are not changed by this release-prep scope. That repository-settings hardening remains a separate operator-authorized action and is not represented as fixed by version `0.10.2`.

## Release boundary

This release-prep candidate does **not** authorize or perform:

- creation of tag `v0.10.2`;
- GitHub Release publication;
- PyPI publication;
- branch-protection/ruleset changes;
- deployment;
- OperationalMemory/R64/current-state mutation;
- agent dispatch;
- trading, wallet, or capital effects.

Tagging and PyPI publication remain separate explicit operator-authorized effects after release-prep review and merge.
