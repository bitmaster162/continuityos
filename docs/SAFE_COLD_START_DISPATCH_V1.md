# Safe Cold-Start Dispatch v1

The installed `continuity` command now treats `cold-start prepare` as a current-
generation safety boundary.

## Default current path

Use:

`continuity cold-start prepare --state-bundle STATE.json --boot-receipt BOOT.json --spec SPEC.json --output OUT`

This routes to the R18-R21 state-bound path before the historical cold-start
preparer can run. Stale lower-authority evidence cannot roll state backward, fresh
current contradictions fail closed, and `PASS_WITH_CONDITIONS` is restricted to
`READ_ONLY`.

## No implicit fallback

Calling `continuity cold-start prepare` without either mode now returns
`CURRENT_COLD_START_HOLD / STATE_BUNDLE_REQUIRED`. It does not silently fall back
to the historical R63-unbound preparer.

## Explicit historical compatibility

The old behavior remains available only with:

`--legacy-r63-unbound`

That flag is intentionally noisy and explicit. It preserves old R63-bound workflows
without allowing them to masquerade as the current guarded path.

All other `continuity` subcommands delegate unchanged to the historical CLI.
The implementation module `continuityos.gate.cli` remains available for historical
code/tests, but the packaged console entrypoint is `continuityos.safe_cli:main`.

This change grants no deployment, Control Center/current-state mutation, trading,
capital, memory activation, external messaging, or self-application authority.
