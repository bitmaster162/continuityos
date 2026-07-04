#!/usr/bin/env bash
# ContinuityOS v0.9 — 90-second feature tour. Uses a throwaway DB (no side effects).
set -e
export CONTINUITYOS_SILENCE_EMBED_WARN=1
if command -v cos >/dev/null 2>&1; then COSBIN="cos"; else COSBIN="python -m continuityos.cli"; fi
DB="$(mktemp -u).db"; COS="$COSBIN --db $DB"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== ContinuityOS v0.9 tour  (memory + continuity + governance, one SQLite file) =="

echo; echo "1) Import your ChatGPT/Claude history (bi-temporal: recall --as-of works):"
$COS import "$HERE/../examples/sample_chatgpt_export.json" -n imported

echo; echo "2) Recall by meaning:"
$COS recall "which license do I like?" -n imported -k 2

echo; echo "3) Key-based upsert (idempotent config) + exact find():"
$COS remember "gpt-5.5"          -n config -K default_model >/dev/null
$COS remember "claude-opus-4-8"  -n config -K default_model >/dev/null
$COS find config default_model

echo; echo "4) Seed canon, export rules into every agent's config (CLAUDE.md/Cursor):"
$COS canon "Agents propose typed intent; deterministic systems dispose." >/dev/null
$COS canon "LLM never controls capital directly." >/dev/null
$COS rules --to claude --stdout | head -9

echo; echo "5) SCAN — reload rule-attention before a critical action (long-session SRD guard):"
$COS scan | head -6

echo; echo "6) RaaS usage metering (plan quota, fail-closed):"
$COS usage --key demo --charge gate.decision

echo; echo "7) Self-update check (PyPI/git, offline-safe):"
$COS update --check

echo; echo "8) Governance gate blocks a catastrophic action:"
python -m continuityos.gate.cli run shell -- rm -rf / 2>/dev/null || echo "   -> DENIED by the gate (rm -rf /)"

echo; echo "== done. Swap the model underneath; \`cos boot\` restores the same agent. =="
