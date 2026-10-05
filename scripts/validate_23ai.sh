#!/usr/bin/env bash
# Run only against the separately pinned 23ai container, never the default testbed.
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_dir"
set -a
. "$repo_dir/testbed/.env"
set +a
export AUTODIAG_TARGETS_FILE="$repo_dir/testbed/targets.23ai.yaml"
export AUTODIAG_SSH_CONFIG="$repo_dir/testbed/ssh_config.23ai"
export AUTODIAG_TESTBED_HOST=autodiag-testbed-23ai
export AUTODIAG_SCAN_ENABLED=false
export AUTODIAG_NOTIFY_COMMAND=""
validation_dir="${AUTODIAG_VALIDATION_DIR:-$(mktemp -d /tmp/autodiag-23ai-validation-XXXXXX)}"
mkdir -p "$validation_dir"
export AUTODIAG_DATA_DIR="$validation_dir/cases"
export AUTODIAG_FAULT_OUT="$validation_dir/faults"
export AUTODIAG_EVAL_FAULT_LOG="$AUTODIAG_FAULT_OUT/faults.log"
export AUTODIAG_EVAL_EXPECT_VERSION_PREFIX=23.9.
banner=$(docker exec -i -u oracle autodiag-oradb-23ai bash -lc 'sqlplus -s / as sysdba' <<'SQL'
whenever sqlerror exit failure
set pages 0 feedback off heading off lines 200
select banner_full from v$version where banner_full like 'Oracle%';
exit
SQL
)
[[ "$banner" == *"Oracle Database 23ai Free"* && "$banner" == *"23.9."* ]] || {
    echo "Refusing validation: database is not the pinned 23ai 23.9 release" >&2
    exit 1
}
printf '%s\nValidation directory: %s\n' "$banner" "$validation_dir"
if [[ "${AUTODIAG_REUSE_FAULT_LOG:-false}" == true ]]; then
    test -s "$AUTODIAG_EVAL_FAULT_LOG"
else
    bash testbed/faults/inject.sh ora600 ora600_repeat ora700 ora7445 ora60 errorstack hang sqltrace_pair opt10053
fi
# Model override is optional and must name an available OpenCode model.
.venv/bin/pytest -v -m 'integration or llm' --junitxml="$validation_dir/live-tests.xml"
