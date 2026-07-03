#!/usr/bin/env bash
set -euo pipefail

echo "ContinuityOS demo: escalate secret reads"
echo

if ! command -v continuity >/dev/null 2>&1; then
  echo "continuity CLI not found. Install the package first:"
  echo '  pip install -e .'
  exit 2
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

secret="$tmpdir/.env"
printf 'API_KEY=demo-only\n' > "$secret"

set +e
continuity preflight shell "cat $secret"
status=$?
set -e

echo
exit "$status"
