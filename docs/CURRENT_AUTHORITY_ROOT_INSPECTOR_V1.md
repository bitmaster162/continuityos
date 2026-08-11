# Current Authority Root Inspector v1 (R31)

R31 removes repetitive path wiring from the current-authority cold-start without introducing discovery heuristics.

## Inspect one stable-root directory

```bash
continuity cold-start inspect-root \
  --authority-root /path/to/current-root \
  --authority-pointer-sha256 <controller-pinned-sha256>
```

The directory must contain these exact canonical files:

- `CURRENT_POINTER.json`
- `CURRENT_STATE.json`
- `ROLE_INDEX.json`
- `ROLE_VIEWS.json`

The inspector never uses globs, timestamps, generation suffixes, fuzzy names, or a "latest" rule. A directory containing only something like `CURRENT_POINTER_R64_ACTIVE.json` fails until the exact canonical `CURRENT_POINTER.json` is present.

Inspection reuses the current cold-start validators to require:

- exact controller-pinned pointer SHA-256;
- `canonical_activation.status=ACTIVE`;
- exact provider readback;
- pointer/root SHA-256 equality;
- matching generation across the stable roots;
- the existing current deny/effect ceilings.

It returns the resolved exact paths and hashes plus generation, activation decision, accepted manifest identity, human sovereign, compiled current-state marker and effect ceiling. It writes nothing.

## Shorter current prepare

The existing long form remains valid. R31 additionally allows:

```bash
continuity cold-start prepare \
  --state-bundle STATE_BUNDLE.json \
  --authority-root /path/to/current-root \
  --authority-pointer-sha256 <controller-pinned-sha256> \
  --spec CURRENT_COLD_START_SPEC.json \
  --output CURRENT_COLD_START
```

`--authority-root` and the individual `--authority-pointer`, `--current-state`, `--role-index`, `--role-views` flags are mutually exclusive. The controller-pinned pointer SHA remains mandatory in both forms.

## Non-claims

R31 does not select or promote authority, rewrite stable-root bytes, mutate Control Center/R64, prepare state without a state-resolution bundle/spec, deploy, dispatch agents, trade, access wallets, or grant capital permission.

`can_trade=false`, `capital_permission=DENY`, and `deploy_permission=DENY` remain unchanged.
