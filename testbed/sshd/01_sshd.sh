#!/usr/bin/env bash
# Startup hook (runs after every database start, as the oracle user):
# 1. export the Oracle environment for non-interactive ssh sessions,
# 2. install the authorized key mounted at /autodiag/authorized_keys,
# 3. start an unprivileged sshd on port 2222 with a persisted host key.
set -u
SSHD_DIR=/home/oracle/sshd
KEY="$SSHD_DIR/ssh_host_ed25519_key"
CONFIG=/home/oracle/sshd_config

mkdir -p "$SSHD_DIR" /home/oracle/.ssh
chmod 700 "$SSHD_DIR" /home/oracle/.ssh

cat > /home/oracle/.autodiag_env <<ENV
export ORACLE_BASE="${ORACLE_BASE:-/opt/oracle}"
export ORACLE_HOME="${ORACLE_HOME:-/opt/oracle/product/23ai/dbhomeFree}"
export ORACLE_SID="${ORACLE_SID:-FREE}"
export PATH="\$ORACLE_HOME/bin:\$PATH"
ENV
grep -q autodiag_env /home/oracle/.bashrc 2>/dev/null || echo '. ~/.autodiag_env' >> /home/oracle/.bashrc

if [ -r /autodiag/authorized_keys ]; then
    cp /autodiag/authorized_keys /home/oracle/.ssh/authorized_keys
    chmod 600 /home/oracle/.ssh/authorized_keys
fi

[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -f "$KEY"
chmod 600 "$KEY"

if [ -f "$SSHD_DIR/sshd.pid" ] && kill -0 "$(cat "$SSHD_DIR/sshd.pid")" 2>/dev/null; then
    echo "autodiag: sshd already running"
    exit 0
fi
rm -f "$SSHD_DIR/sshd.pid"
/usr/sbin/sshd -f "$CONFIG" -E "$SSHD_DIR/sshd.log" && echo "autodiag: sshd started on port 2222"
