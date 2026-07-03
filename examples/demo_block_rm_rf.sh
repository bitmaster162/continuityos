#!/usr/bin/env bash
set -euo pipefail

echo "ContinuityOS demo: block recursive force delete"
echo

if ! command -v continuity >/dev/null 2>&1; then
  echo "continuity CLI not found. Install the package first:"
  echo '  pip install -e .'
  exit 2
fi

set +e
continuity preflight shell "rm -rf /"
status=$?
set -e

exit "$status"
