#!/usr/bin/env bash
# Record docs/demo/autodiag.cast with asciinema and render docs/demo/autodiag.gif with agg
# (https://github.com/asciinema/agg). Needs a reachable target with at least one ADR
# problem; see record.sh for the DEMO_* variables.
#
#   AGG=/path/to/agg AGG_FONT_DIR=/path/to/ttf docs/demo/make.sh
#
# The recording is scrubbed of the local home path and hostname so that it only shows
# what the CLI printed; anything else that identifies the environment fails the build.
set -euo pipefail
cd "$(dirname "$0")"
: "${AGG:=agg}"
: "${AGG_FONT_DIR:=}"
: "${COLS:=100}"
: "${ROWS:=32}"

asciinema rec --overwrite --quiet --cols "$COLS" --rows "$ROWS" --idle-time-limit 2 \
    -t "AutoDiag: automated diagnosis of an ADR problem" -c ./record.sh autodiag.cast

host=$(hostname -s)
sed -i -e "s#${HOME//#/\\#}#~#g" -e "s#${host}#host#g" autodiag.cast
if grep -qiE "${HOME}|${host}" autodiag.cast; then
    echo "make.sh: the recording still contains local identifiers" >&2
    exit 1
fi

"$AGG" ${AGG_FONT_DIR:+--font-dir "$AGG_FONT_DIR"} --font-size 14 --line-height 1.35 \
    --theme github-dark --idle-time-limit 2 --last-frame-duration 5 \
    autodiag.cast autodiag.gif
ls -l autodiag.cast autodiag.gif
