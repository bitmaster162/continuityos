# Company Twin Client Demo R1 — Northstar Labs (FICTIONAL)

**Status:** local synthetic-only client showcase candidate / not production admitted.
**Git baseline:** protected master `517c7b48e270a3077e53d890e907c9cb2b3ce491` (tree `fcb37ef8d9af2c349a62c576b5634798881a7fbe`).
**Scope:** one isolated demo branch and one PR (Draft until checks and review-ready gate); no merge, deploy, scheduler/TPM, live connectors, real model, external API, or real data.

## Product in one sentence

ContinuityOS reconstructs a company's evidence-backed history and decisions at a selected point in time, with Director / Worker / Managed-Agent access constraints. The example company **Northstar Labs** is entirely fictional.

## What this actually uses

- **P2A** `continuityos.company_twin.load_dataset/replay` and the existing `northstar_labs_2025.json` 12-month synthetic fixture.
- **P2C** `continuityos.company_twin_policy.evaluate` via the existing P2D `build_snapshot`: tenant/scope/role/delegation checks.
- **P2D** `continuityos.company_twin_console.make_server` and its existing GET `/api/snapshot`, HEAD, HTTP-405 write denials, loopback-only bind and unchanged policy filtering.
- **New demo-only presentation adapter:** `demo/company_twin_client_demo.py`, standalone HTML page, synthetic actor/grant metadata, synthetic emails/tasks, human-authored demo decision attribution.
- **P2B ingestion and P2E live/self-pilots are not executed**. The new synthetic email/task records are P2A-compatible fixtures, not real connectors.
- **Person Twin #211 is already merged**; demo does not consume new #212–#215 features or modify the Person Twin production/evidence path.

This PR adds NO new memory/policy/agent/runtime core and modifies NO existing tracked files.

## 10-minute client walkthrough

| Time | Action | Observable result |
| --- | --- | --- |
| 0–1 min | Open Northstar Labs view as **Alice Chen / Director** | 12 fictional humans, 3 teams, one managed research agent |
| 1–3 min | Scroll the company timeline | Synthetic documents, email/task events, decisions and outcomes covering 2025 |
| 3–5 min | Open Decision Ledger | For each authorized decision: date, fictional decision author, rationale, evidence title(s), ACTIVE/SUPERSEDED status |
| 5–7 min | Click **Mar 31**, then **Dec 31** | Replayed authorized decision/event set changes; March's paid-acquisition pause becomes SUPERSEDED by the September partner-qualified decision |
| 7–9 min | Switch **Director → Bob (Sales) → Cara (Engineering) → Atlas Agent** | Sales cannot see restricted finance or engineering; agent sees scoped engineering data and READ/PROPOSE but not APPROVE/EXECUTE |
| 9–10 min | Show pending Atlas proposal and policy status | Proposal needs human review; no external action, approval, or execution endpoint exists |

Dates are selectable within **2025**, the period of the provided historical dataset. Dates outside this dataset are not claimed to be supported.

## Local demo commands (local execution, no cloud dependencies)

From a clean verified source checkout on Windows or Linux:

```powershell
python -B -m demo.company_twin_client_demo --check
python -B -m demo.company_twin_client_demo
```

Open `http://127.0.0.1:8769/`. Use Ctrl+C to stop. Server refuses non-loopback bindings. Port may be changed with `--port 0` for tests or `--port 8770` for another local session.

Bounded local tests, without auto-loading extra pytest plugins and without writing cache or bytecode:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -B -m pytest -q -p no:cacheprovider tests/test_company_twin_client_demo.py tests/test_company_twin.py tests/test_company_twin_policy.py tests/test_company_twin_console.py tests/test_company_twin_ingest.py
```

No need for Docker, browser extensions, SSH, API keys, a paid model, or credentials.

## Wheel-only qualification boundary

The client presentation adapter lives under `demo/` in a source checkout; it is
**not packaged into the core ContinuityOS wheel**. CI tests the demo from the
clean source and editable checkout. When the isolated wheel-only runner copies
the `tests/` directory without `demo/`, this exact new demo-test module is
**explicitly skipped** after checking that no source file is available; existing
wheel-portable P2A/P2C/P2D test coverage remains required. A wheel skip is
recorded as SKIP, never PASS. This is an intentional packaging boundary, not a
silent fallback or a claim that the installed wheel serves the demo.
## Truth and authorization claims

- **SYNTHETIC DATA ONLY**. Names, company, emails, tasks, source references, roles and decision authors are made up.
- All evidence is marked `EVIDENCE`, history is `FACT`, interpretation stays `INFERENCE`.
- Decision `decided_by_name` and `decided_by_principal` are **fictional demo metadata**; they are not cryptographically signed, authentic user identities, verified approvals, or a proof of source authorship.
- The role selector **simulates viewpoints; it is not authentication**. It is never advertised as a production identity/SSO gate.
- P2A's replay covers only existing dates and applies explicit record scope. P2D intersects P2A with P2C and hides unauthorized rows, IDs and decision lineage.
- Agent is assigned a named human manager plus an explicit Director-issued, time-limited delegation to `team:engineering`; `READ/PROPOSE` are authorized *policy classes*, not HTTP mutation endpoints.
- Every actual HTTP write method (`POST/PUT/PATCH/DELETE`) is rejected. `EXECUTE` does not exist as a P2C action, and `can_execute=false` in runtime and governance outputs.
- External network isolation is a *design boundary of the demo package*, not an OS-level sandbox claim. Server listens only on loopback; the code never fetches real sources or calls LLMs.
- No real ContinuityOS, Robert, client, Gmail, Drive, Slack, GitHub, finance, secrets, private repos or other protected data enter the fixture.

## Verification and release

A customer demo should only be called ready after deterministic local tests and a live local 10-minute walkthrough (browser visual quality / client presentation) are checked. An offline HTTP smoke is not a production penetration test.

### Verified CI on exact reviewed HEAD (2026-10-16)

The exact reviewed code HEAD `82bb250c36e25c35df8890c29c5d920dc4e4c3a8` completed all five GitHub checks with **SUCCESS**:
- `review-gates` [run 38837817465](https://github.com/bitmaster162/continuityos/actions/runs/38837817465): Ubuntu / Python 3.11 **SUCCESS** and Windows / Python 3.11 **SUCCESS**.
- `CodeQL` [run 38837817437](https://github.com/bitmaster162/continuityos/actions/runs/38837817437): CodeQL **SUCCESS**, Analyze Python **SUCCESS**.
- `P0 Unified Shadow Continuity` [run 38837817510](https://github.com/bitmaster162/continuityos/actions/runs/38837817510): offline-shadow-continuity **SUCCESS**.

Ubuntu source/editable: 2502 passed / 67 skipped; isolated wheel: 2419 passed / 118 skipped. Windows source/editable: 2510 passed / 59 skipped; isolated wheel: 2420 passed / 117 skipped. Each test mode also recorded 870 passing subtests. Wheel-only deliberately skips the checkout-only demo test; it does not mark that module as passed.

These checks are evidence for the **named HEAD only**. After the documentation-only follow-up commit, all required checks must complete successfully on the **new exact HEAD** before Draft is changed to Ready for review. Full CI is not permission to merge. Merge requires a separate human decision bound to base/head/tree and ordinary merge-commit method. Do not bypass protected-master requirements. No manual workflow reruns, merges, releases, deployment or branch deletion are authorized by this document.

**Historical planning estimate (not an elapsed-time claim):** initially 1–2 focused engineering days for the fixture/presentation/tests and 0.5–1 additional day for visual review. The demo implementation and the listed exact-HEAD CI now exist; client presentation signoff, fresh new-HEAD checks, human review and merge authorization remain separate gates.

## Stop conditions

- Git base/head tree changes unexpectedly, or tracked files outside the four new demo/test/docs files change.
- Any real input, production authorization, external connection or delegated agent EXECUTE emerges.
- A non-loopback host is requested.
- Any P2A/P2C/P2D permission regression is observed.
- CI absent, failed, or not associated with the current exact HEAD: keep as Draft/HOLD until all required checks pass. Never treat a prior-head success as current-head qualification, or call this production-qualified.

Unchanged / on HOLD: H3 PR #209/#210, Person Twin PR #212–#215, production admission C0/T11/T12 and all capital/TPM/Scheduler authority.
