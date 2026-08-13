# ContinuityOS 0.10.3 — Release Preparation Notes

Status: **release-prep candidate; not tagged or published**.

This patch release carries two post-0.10.2 repository hardening changes into a new package identity instead of modifying or reusing the already-published `0.10.2` artifacts.

## What changed after 0.10.2

### Canonical Apache-2.0 license integrity

The root `LICENSE` was restored to the complete canonical Apache License 2.0 text after the previous repository copy was found to be truncated in Section 4/5.

Dedicated regression coverage now verifies both source and installed-wheel license identity, including:

- the previously missing Apache-2.0 clauses;
- the canonical appendix placeholder;
- `License-Expression: Apache-2.0` package metadata;
- packaged `LICENSE` and `NOTICE` file declarations.

GitHub license detection subsequently resolves the repository as `Apache-2.0` rather than `NOASSERTION`.

### PyPI Trusted Publishing workflow

The publish workflow no longer passes the long-lived `PYPI_API_TOKEN` secret to `pypa/gh-action-pypi-publish`.

The publish job retains the existing GitHub environment and OIDC permission:

```yaml
environment:
  name: pypi

permissions:
  id-token: write
```

The configured action therefore uses the PyPI Trusted Publishing / GitHub OIDC path when a matching publisher is registered on PyPI.

The repository-side migration is complete, but the OIDC cutover is not represented as end-to-end proven by this release-prep candidate. The proof boundary is a successful separately authorized `v0.10.3` tag-triggered publish with no long-lived password input.

## Version identity

Canonical package version for this candidate:

```text
0.10.3
```

`cos --version` and package metadata derive from the same canonical `continuityos._version.__version__` value.

## Compatibility

- Python 3.10+
- stdlib-only core remains supported
- optional embedding extras remain opt-in
- canonical `cos = continuityos.current_entrypoints:cos_main` entrypoint remains unchanged

## Release boundary

This release-prep candidate does **not** authorize or perform:

- creation of tag `v0.10.3`;
- GitHub Release publication;
- PyPI publication;
- deletion of any GitHub/PyPI credential or secret;
- deployment;
- OperationalMemory/R64/current-state mutation;
- agent dispatch;
- trading, wallet, or capital effects.

Tagging and PyPI publication remain separate explicit operator-authorized effects after release-prep review and merge.
