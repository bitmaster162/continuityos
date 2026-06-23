#!/usr/bin/env bash
# 60-second killer demo: ContinuityOS prevents a destructive agent action.
set -e
echo "== ContinuityOS killer demo: prevented incident =="
continuity init >/dev/null 2>&1 || python -m continuityos.gate.cli init >/dev/null
echo; echo "1) An agent (or you) tries a catastrophic delete:"
echo "   $ continuity run shell -- rm -rf /"
python -m continuityos.gate.cli run shell -- rm -rf / || true
echo; echo "2) The same, via the Claude Code hook (what the real agent sees):"
echo '   {"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | python -m continuityos.gate.claude_hook || true
echo; echo "3) A safe command sails through:"
echo "   $ continuity run shell -- echo build-ok"
python -m continuityos.gate.cli run shell -- echo build-ok
echo; echo "4) Tamper-evident audit trail:"
python -m continuityos.gate.cli audit -n 5
