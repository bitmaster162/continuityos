# ContinuityOS governance repair status — 2026-07-12

## Verdict

**TEN HARDENING PROBES PASS; MANDATORY BROKER REMAINS HOLD.**

The controlled continuity-run path is locally proof-backed. The MCP preflight remains
advisory, and no claim is made that raw shells, SDKs, or unconfigured hosts are intercepted.
The local Hermes hook configuration is not active: the inspected hook block is commented out.
No commit or push was performed. can_trade=false.

Repository identity for this pass:

    root:        C:\PROJECTS\continuityos
    branch:      master
    HEAD before: fff3ecc2f83238d909eadf2f6e73eba33cca93d3
    HEAD after:  fff3ecc2f83238d909eadf2f6e73eba33cca93d3
    platform:    Windows-10-10.0.26200-SP0
    Python:      3.11.9 (MSC v.1938 64 bit)

The sibling C:\PROJECTS\continuity_os canonical runtime was not mutated.

## Exact local receipts

Current working tree:

    python -m pytest -q
    256 passed, 1 skipped in 38.11s

    python tests/release_hardening_probes.py
      --json-out C:\Users\coins\Downloads\continuityos_probe_results_20260712.json
    10/10 PASS; all_passed=true; 48.806s

    python -m bench.continuitybench
    30/30 labeled agreement
    22/22 risky cases not auto-run
    0/7 safe-ALLOW false positives in the fixed corpus
    8/8 adversarial cases not auto-run

    python -m compileall -q continuityos tests bench gate_hook.py
    COMPILEALL_OK

Clean patched source clone, fresh venv, no installed ContinuityOS metadata:

    root:
    C:\Users\coins\AppData\Local\Temp\continuityos_release_verify_20260712_075210

    CONTINUITYOS_METADATA=ABSENT
    python -m pytest -q
    256 passed, 1 skipped in 22.24s

Editable install in a separate venv:

    pip install -e .
    EDITABLE_VERSION=0.9.0
    METADATA_VERSION=0.9.0
    python -m pytest -q
    256 passed, 1 skipped in 19.24s

Standard isolated PEP 517 wheel build and an external wheel-only test workspace:

    pip wheel --no-deps -w wheelhouse .
    continuityos-0.9.0-py3-none-any.whl
    SHA-256 e410e3305d61a71818148cc04f895211bb89821fdc61d7790bf2fa865a51d28c

    IMPORT_PATH=...\site-packages\continuityos\__init__.py
    WHEEL_VERSION=0.9.0
    METADATA_VERSION=0.9.0
    python -m pytest -q --import-mode=importlib
    256 passed, 1 skipped in 25.00s

An initial diagnostic --no-build-isolation wheel attempt failed because the venv's old
setuptools rejected the PEP 621 license string. The standard build-isolated path installed
the declared build dependency and succeeded; the successful wheel above is the release receipt.

CRLF-aware and secret checks:

    git diff --check
    PASS (core.autocrlf=true emitted conversion notices only)

    tracked diff files: 30
    content-diff files: 30
    line-ending-only files: 0

    high-confidence credential scan:
    129 canonical tracked/new files scanned
    0 private-key / AWS / GitHub / OpenAI / Anthropic / Slack / Google / Stripe-live hits
    SECRET_SCAN_PASS

Windows CI-equivalent commands (editable/full pytest, portable probes, benchmark) passed locally.
The GitHub workflow now carries the portable probes on Ubuntu/Python 3.11 and Windows/Python 3.11,
but there is **no remote Windows or Linux CI receipt for this dirty tree** because this pass stops
before commit/push. Remote CI therefore remains HOLD, not silently reported as green.

## Ten probe outcomes

1. Version identity — one _version.py source; clean source/editable/wheel all report 0.9.0.
2. Protected delete — aliases, wrappers, subshells, path-qualified tools and typed delete remain
   DRY_RUN_ONLY/DENY; ordinary confirmation cannot execute them.
3. Policy schema — unknown top-level and nested fields fail with exact field paths.
4. Ledger export — full hash, prev_hash, exact raw payload, deterministic timestamp text and
   scheme permit offline chain recomputation.
5. LedgerSink — process locks, atomic replacement, crash recovery, ACK validation, generation
   ordering and torn-line quarantine prevent silent loss in the tested races.
6. MCP — exact args are required, command/argv divergence holds or denies, and max_args
   is enforced.
7. Hermes cwd — terminal workdir overrides session cwd, malformed shapes block, and unsupported
   execute_code is blocked rather than falsely treated as covered.
8. Hermes/context DB — explicit/env/default resolution is deterministic; missing configured
   authority holds; live SQLite path and logical canon/rules digest are bound to result and ledger
   inside one read snapshot.
9. CLI dry-run — one structured executed=false result with dedicated exit code 3.
10. Execution receipts — execution requires a real matching ledger preflight, executable decision,
    exact action/tool/cwd/argv/rollback plan and any required human override; lifecycle events bind
    started/completed/failed, exit code and rollback receipt.

## Repair manifest

The non-self-referential repair manifest covers 36 sorted canonical files, excluding this status
document. It hashes UTF-8 rows of relative-path, tab, file-sha256, newline:

    e8cd01bc41605ad954845ef75ffd75d2ab2b4efa3a25a622078550282482ee04

The staged manifest (which includes this document) must be computed after selective staging and is
reported in the operator return bundle. Root ad-hoc tests, local policy, release scripts, and
_RUN_ORCA_PILOT.bat are excluded.

## Residual HOLDs

1. **No mandatory boundary.** The real Hermes hook is not enabled, and raw tools can bypass the
   controlled runner. execute_code is deliberately blocked by the bridge because reducing it to
   one shell command would be false coverage.
2. **No remote CI receipt.** Linux/Windows workflow execution needs a later operator-authorized
   commit/push.
3. **Classifier ceiling.** Signals and paths are conservatively associated across a whole command;
   false positives are possible, and patterns are not a shell parser or sandbox.
4. **Context digest scope.** The digest covers logical canon/rules item rows, not FTS auxiliary
   state or the runtime embedder; it is identity evidence, not complete replay evidence.
5. **Ledger authenticity.** Hash chains are tamper-evident but unsigned and not externally
   anchored. LedgerSink is at-least-once: an ambiguous accepted HTTP response or crash can replay
   an event. Quarantine is durable local evidence, not part of the central hash chain.
6. **Terminal ambiguity.** If execution finishes but the terminal ledger append fails, exit 4
   and a best-effort local ambiguity journal warn against blind retry; total disk failure can also
   defeat that fallback.
7. **TOCTOU and rollback limits.** Paths can change after preflight. Directories, symlinks and
   external effects still need a capability-owning broker and upstream compensation/idempotency.

## Next irreversible action

After operator review, commit the selectively staged repair, run remote Linux and Windows CI, then
physically enable and prove one Hermes terminal interception path. Do not enable trading or claim
universal enforcement before that boundary receipt exists.
