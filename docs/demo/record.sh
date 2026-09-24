#!/usr/bin/env bash
# Scripted terminal session for the README animation. It runs the real CLI against a
# configured target; only the keystrokes and the line-by-line reveal of the output are
# simulated so that a viewer can follow. Recorded by make.sh, or run it directly.
set -u
TARGET="${DEMO_TARGET:-testbed}"
KEY="${DEMO_PROBLEM_KEY:-ORA 600 [autodiag_repeat]}"
CHAR_DELAY="${DEMO_CHAR_DELAY:-0.08}"   # per two characters
LINE_DELAY="${DEMO_LINE_DELAY:-0.06}"   # per line, plus 0.8 ms per character
SECTION_PAUSE="${DEMO_SECTION_PAUSE:-1.8}"
PROMPT=$'\e[1;32m$\e[0m '

type_cmd() {  # print the prompt, then the command two characters at a time
    printf '%s' "$PROMPT"
    local s="$1" i
    for ((i = 0; i < ${#s}; i += 2)); do
        printf '%s' "${s:i:2}"
        sleep "$CHAR_DELAY"
    done
    sleep 0.7
    printf '\n'
}

reveal() {  # pace the output at reading speed: longer lines and new sections wait more
    local line plain
    while IFS= read -r line; do
        plain=$(printf '%s' "$line" | sed -E 's/\x1b\[[0-9;]*m//g; s/\r$//')
        case "$plain" in
            Concerns*|Dismissed*|"Suggested actions"*|"Open questions"*|"Evidence considered"*)
                sleep "$SECTION_PAUSE" ;;
        esac
        printf '%s\n' "$line"
        sleep "$(awk -v n="${#plain}" -v d="$LINE_DELAY" 'BEGIN { printf "%.3f", d + n * 0.0008 }')"
        case "$plain" in
            CRITICAL:*|WARNING:*|INFO:*) sleep 2.5 ;;
        esac
    done
}

run() {  # run under a pty so the CLI keeps its colours, then pace the output
    script -qefc "$1" /dev/null | reveal
}

sleep 0.8
type_cmd "autodiag adr problems -t $TARGET"
run "autodiag adr problems -t $TARGET"
sleep 2.5
type_cmd "autodiag diagnose problem -t $TARGET -k \"$KEY\""
run "autodiag diagnose problem -t $TARGET -k '$KEY'"
sleep 1
printf '%s' "$PROMPT"
sleep 4
