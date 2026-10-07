#!/usr/bin/env bash
# Run after Grid root scripts finish. No host SSH changes; only a lab login is added.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
public_key=${1:?Path to the dedicated lab SSH public key}
[[ $public_key == *.pub && -f $public_key ]] || exit 1
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for node in autodiag-rac1 autodiag-rac2; do
    [[ $(podman inspect -f '{{index .Config.Labels "autodiag.lab"}}' "$node") == rac26ai ]]
    podman exec "$node" bash -c '
        command -v sudo >/dev/null
        id autodiag >/dev/null 2>&1 || useradd -m -s /bin/bash autodiag
        install -d -m 700 -o autodiag -g autodiag /home/autodiag/.ssh
    '
    podman cp "$public_key" "$node:/home/autodiag/.ssh/authorized_keys"
    podman cp "$script_dir/sudoers-autodiag" "$node:/etc/sudoers.d/autodiag"
    podman cp "$script_dir/sshd-autodiag.conf" "$node:/etc/ssh/sshd_config.d/90-autodiag.conf"
    podman exec "$node" bash -c '
        chmod 440 /etc/sudoers.d/autodiag
        visudo -cf /etc/sudoers.d/autodiag
        chown autodiag:autodiag /home/autodiag/.ssh/authorized_keys
        chmod 600 /home/autodiag/.ssh/authorized_keys
        sshd -t
        systemctl reload sshd
        passwd -d autodiag >/dev/null
    '
    # RAC's setgid oracle executable clears dumpability; /proc links then need
    # SYS_PTRACE. Grant it only to a dedicated diagnostic sshd, not the node.
    # exec --privileged makes the capability available; setpriv drops every
    # capability except sshd's normal root needs plus SYS_PTRACE before exec.
    if ! podman exec "$node" bash -c 'test -s /run/autodiag-sshd.pid && kill -0 "$(cat /run/autodiag-sshd.pid)"'; then
        podman exec --privileged -d "$node" setpriv \
            --bounding-set=-all,+chown,+dac_override,+fowner,+fsetid,+kill,+setgid,+setuid,+setpcap,+net_bind_service,+sys_chroot,+audit_write,+audit_control,+setfcap,+sys_ptrace \
            /usr/sbin/sshd -D -p 2222 -o PidFile=/run/autodiag-sshd.pid \
            -o AllowUsers=autodiag -o PasswordAuthentication=no \
            -o KbdInteractiveAuthentication=no -o AuthenticationMethods=publickey
    fi
done
