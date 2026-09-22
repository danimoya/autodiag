#!/usr/bin/env bash
# Fails if any tracked or untracked (non-ignored) file contains an environment-specific
# identifier. The repository must stay environment-neutral; real hosts belong in
# git-ignored configuration. The pattern is assembled from fragments so that this
# script does not trip itself.
set -euo pipefail
cd "$(dirname "$0")/.."
PATTERN="g""pc|100\.64\.|ola""res|dm""26"
files=$(git ls-files --cached --others --exclude-standard | grep -vE '^(\.venv/|data/)' || true)
[ -z "$files" ] && exit 0
if echo "$files" | xargs -d '\n' grep -nIiE "$PATTERN" -- 2>/dev/null; then
    echo "hygiene: environment-specific identifiers found" >&2
    exit 1
fi
