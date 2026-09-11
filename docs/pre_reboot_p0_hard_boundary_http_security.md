# Pre-reboot P0 hard boundary and HTTP security

Status: local candidate only; no commit/push/PR/merge/reboot/TPM/deploy.

Exact base:
- master: `8cc6a6aa2d31ac4a983fb31ff8b82cbe1739a850`
- tree: `cc906b1b0d4f6687285fb62a8c42c14eb573862f`
- branch: `agent/pre-reboot-p0-hard-boundary-http-security-r1`

## Problem closed by this candidate

The historical command-risk classifier recognized destructive syntax, but ordinary
external effects could still be syntactically benign. In particular, exact broker
preflight could classify package mutation, remote merge, HTTP writes, or infrastructure
apply as `ALLOW` when no older regex happened to match.

A second seam existed in the optional local HTTP API: loopback requests could be
tokenless while wildcard CORS allowed browser origins to reach the API surface.
## Effect classification v1

Preflight now derives an effect record from the exact typed `ActionSpec`.
Callers do not supply effect authority. The record is persisted in the preflight
ledger receipt and is validated by GateBroker when present.

Default effect policy:
- local read: `ALLOW`
- local mutation: existing path/risk policy remains authoritative
- dynamic command/eval carrier: `REQUIRE_CONFIRMATION`
- network read: `ALLOW`
- network write: `REQUIRE_CONFIRMATION`
- package mutation: `REQUIRE_CONFIRMATION`
- Git remote mutation: `REQUIRE_CONFIRMATION`
- cloud CLI boundary: at least `REQUIRE_CONFIRMATION`
- cloud mutation: `HOLD`
- infrastructure mutation: `HOLD`
- remote shell: `HOLD`
- remote artifact mutation: `REQUIRE_CONFIRMATION`
- unknown executable: `REQUIRE_CONFIRMATION`

The first bounded command families include Git/GitHub remote state, package managers,
HTTP clients, cloud CLIs, Terraform/OpenTofu, Kubernetes/Helm, remote shells/transfers,
container-registry pushes, and common interpreter/eval carriers.

This does **not** claim semantic understanding of arbitrary code executed inside an
otherwise admitted binary or script. Unknown application logic remains outside this
classifier's proof ceiling. A future mandatory host boundary must also remove direct/raw
tool bypasses; installation alone is still not universal interception.

## HTTP boundary

Browser-origin access is denied by default. There is no wildcard CORS response.
An allowed browser origin must be configured explicitly and requires a bearer token.
Non-loopback bind additionally requires both `CONTINUITYOS_ALLOW_REMOTE=1` and
`CONTINUITYOS_TOKEN`.

Requests without an `Origin` header retain local CLI/curl compatibility on loopback.
This does not turn the stdlib HTTP server into an Internet-facing production service.


## Historical receipt rule

Pre-effect-classification broker receipts remain readable for custody and cached terminal
history. They do not authorize a fresh execution attempt after this upgrade. A pending or
unused historical preflight must be re-preflighted so the exact action receives an effect-v1
record under the current policy.

For effect-v1 receipts, GateBroker recomputes the classification from the ledger-bound exact
action and rejects shape-valid but forged/mismatched effect records.

This prevents old/orphan preflight authority from bypassing the new hard-boundary policy.

## Typed local mutation vs CLI local mutation

Local file tools and arbitrary CLI mutation are not equivalent authority.
`file.write` / `file.delete` receive `TYPED_LOCAL_MUTATION`; the exact paths are part of the ActionSpec and existing rollback/protected-path logic remains authoritative.
CLI actions such as `git fetch`, `gh release download`, `terraform init`, and container runtime mutations receive `LOCAL_MUTATION`, whose default minimum decision is `REQUIRE_CONFIRMATION`.
A CLI-local mutation with no declared rollback targets also records `local mutation has no typed rollback target paths`.
This avoids treating caller-supplied/inferred filenames as proof of a process's complete effect set.

## ContinuityBench contract update

The P0 boundary intentionally reclassifies project-code/hook carriers as GATE rather than ALLOW:
- `npm test`
- `npm run build`
- `python build.py`
- `git commit ...` (hooks may execute code)
- `pytest -q`

This is a security-contract change, not a benchmark relaxation: each command can execute repository-controlled code or hooks.
The updated corpus still requires exact labeled agreement and separately preserves explicit read-only ALLOW cases such as `ls` and `git status`.

## Adversarial effect-matrix acceptance

Before final source freeze, a 30-case cross-surface matrix was evaluated against an outside-HOME cwd so protected-path policy could not mask effect decisions.
The matrix covers Git/GitHub, curl/wget, package/test/project-code carriers, PowerShell/cmd/bash, Terraform/Kubernetes/Helm, SSH/SCP, cloud CLIs, Docker registry mutation, and an unknown executable.
Acceptance result: 30/30 exact expected decisions; 0 mismatches.
Explicit read-only examples (`git status`, `git diff`, `python --version`, curl GET, `git ls-remote`, GitHub PR view, wget-to-stdout) remain ALLOW.
All dynamic/project-code and unknown executables require confirmation; infrastructure, remote shell, and destructive cloud mutations HOLD.
