#!/usr/bin/env bash
# Run fault scripts against the testbed. Usage: inject.sh [all | name ...]
. "$(dirname "$0")/_lib.sh"
ALL=(ora600 ora600_repeat ora700 ora7445 ora60 errorstack hang sqltrace_pair opt10053 ora1578 ora1555)
BEST_EFFORT=(ora1578 ora1555)
if [ $# -eq 0 ] || [ "$1" = all ]; then set -- "${ALL[@]}"; fi
: > "$OUT_DIR/faults.log"
fail=0
for f in "$@"; do
    echo "=== $f"
    if ! "$FAULTS_DIR/$f.sh"; then
        if printf '%s\n' "${BEST_EFFORT[@]}" | grep -qx "$f"; then
            echo "    (best effort, not counted as failure)"
        else
            fail=1
        fi
    fi
done
echo; echo "=== summary ($OUT_DIR/faults.log)"; cat "$OUT_DIR/faults.log"
exit $fail
