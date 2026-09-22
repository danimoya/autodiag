#!/usr/bin/env bash
# Install the AutoDiag skill, agent and commands into the OpenCode user configuration.
# Usage: opencode/install.sh [--config-dir ~/.config/opencode] [--merge]
#   --merge  also merge opencode.json.example's "mcp.autodiag" entry into opencode.json (needs jq)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG="${HOME}/.config/opencode"
MERGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --config-dir) CFG="$2"; shift 2 ;;
        --merge) MERGE=1; shift ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done
mkdir -p "$CFG/skills" "$CFG/agents" "$CFG/commands"
cp -r "$HERE/skills/autodiag-oracle" "$CFG/skills/"
cp "$HERE/agents/autodiag-triage.md" "$CFG/agents/"
cp "$HERE"/commands/*.md "$CFG/commands/"
echo "installed skill, agent and commands into $CFG"
if [ "$MERGE" = 1 ]; then
    command -v jq >/dev/null || { echo "jq is required for --merge" >&2; exit 1; }
    bin="$(command -v autodiag || true)"
    [ -n "$bin" ] || { echo "autodiag is not on PATH; activate the venv first" >&2; exit 1; }
    tmp="$(mktemp)"
    if [ -f "$CFG/opencode.json" ]; then cp "$CFG/opencode.json" "$tmp"; else echo '{}' > "$tmp"; fi
    jq --arg bin "$bin" '.mcp.autodiag = {type: "local", command: [$bin, "mcp", "stdio"], enabled: true, timeout: 15000}' "$tmp" > "$CFG/opencode.json"
    rm -f "$tmp"
    echo "merged mcp.autodiag into $CFG/opencode.json"
else
    echo "add the mcp.autodiag entry from $HERE/opencode.json.example to $CFG/opencode.json (or rerun with --merge)"
fi
if command -v autodiag >/dev/null; then autodiag mcp selftest | head -2; fi
