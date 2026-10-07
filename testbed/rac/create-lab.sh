#!/usr/bin/env bash
# Disposable, single-host development lab; never pass an existing block device.
# Run as root after reviewing subnet/resource choices and importing the RAC image.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
lab_dir=${1:?Specify a new absolute lab storage directory outside the repository}
[[ $lab_dir == /* && ! -e $lab_dir ]] || { echo 'Storage directory must be new.' >&2; exit 1; }
rac_image=localhost/autodiag-rac:26ai-lab
podman image exists "$rac_image"
podman image exists localhost/autodiag-rac-dns:lab
for name in autodiag-rac1 autodiag-rac2 autodiag-rac-dns; do
    if podman container exists "$name"; then echo "Already exists: $name" >&2; exit 1; fi
done
for name in autodiag-rac-pub autodiag-rac-priv1 autodiag-rac-priv2; do
    if podman network exists "$name"; then echo "Already exists: $name" >&2; exit 1; fi
done
if podman secret inspect autodiag-rac-password >/dev/null 2>&1; then
    echo 'Lab password secret already exists.' >&2; exit 1
fi
# Fail before allocation if any host route overlaps one of the lab subnets.
ip -j -4 route | python3 -c '
import ipaddress, json, sys
labs = [ipaddress.ip_network("10.203.%d.0/24" % n) for n in range(3)]
for route in json.load(sys.stdin):
    dst = route.get("dst", "default")
    if dst != "default" and any(ipaddress.ip_network(dst).overlaps(n) for n in labs):
        sys.exit("Route overlaps lab subnet: " + dst)
'
install -d -m 700 "$lab_dir"
fallocate -l 60G "$lab_dir/asm-data.img"
chmod 600 "$lab_dir/asm-data.img"
asm_loop=$(losetup --find --show "$lab_dir/asm-data.img")
echo "Dedicated ASM device: $asm_loop backed by $lab_dir/asm-data.img"
# Only this newly created loop device is exposed to the RAC nodes.
openssl rand -base64 30 | tr -d '\n' | base64 | podman secret create autodiag-rac-password -
podman network create --subnet 10.203.0.0/24 --disable-dns autodiag-rac-pub
podman network create --subnet 10.203.1.0/24 --disable-dns --internal autodiag-rac-priv1
podman network create --subnet 10.203.2.0/24 --disable-dns --internal autodiag-rac-priv2
podman run -d --name autodiag-rac-dns --label autodiag.lab=rac26ai \
    --network autodiag-rac-pub:ip=10.203.0.53 --memory 256m --cpus 1 \
    localhost/autodiag-rac-dns:lab
for node in 1 2; do
    podman create -t -i --name "autodiag-rac$node" --hostname "rac$node" \
        --label autodiag.lab=rac26ai --systemd=always --cgroupns=private \
        --network "autodiag-rac-pub:ip=10.203.0.1$node,interface_name=eth0" \
        --network "autodiag-rac-priv1:ip=10.203.1.1$node,interface_name=eth1" \
        --network "autodiag-rac-priv2:ip=10.203.2.1$node,interface_name=eth2" \
        --dns 10.203.0.53 --dns-search rac.test \
        --shm-size 4G --cpus 4 --memory 16G --memory-swap 16G \
        --sysctl kernel.shmall=2097152 --sysctl kernel.shmmax=8589934592 \
        --sysctl kernel.shmmni=4096 --sysctl 'kernel.sem=250 32000 100 128' \
        --sysctl net.ipv4.conf.eth1.rp_filter=2 --sysctl net.ipv4.conf.eth2.rp_filter=2 \
        --cap-add SYS_RESOURCE --cap-add NET_ADMIN --cap-add SYS_NICE \
        --cap-add AUDIT_WRITE --cap-add AUDIT_CONTROL --cap-add NET_RAW \
        --ulimit rtprio=99 --ulimit nofile=65536:65536 --ulimit memlock=-1:-1 \
        --secret autodiag-rac-password \
        --device "$asm_loop:/dev/asm-disk1" \
        -e PASSWORD_FILE=autodiag-rac-password -e DNS_SERVERS=10.203.0.53 \
        -e PUBLIC_HOSTS_DOMAIN=rac.test \
        -e 'CRS_NODES=pubhost:rac1,viphost:rac1-vip;pubhost:rac2,viphost:rac2-vip' \
        -e "CRS_PRIVATE_IP1=10.203.1.1$node" -e "CRS_PRIVATE_IP2=10.203.2.1$node" \
        -e SCAN_NAME=rac-scan -e INSTALL_NODE=rac1 -e OP_TYPE=setuprac \
        -e CRS_ASM_DEVICE_LIST=/dev/asm-disk1 -e 'CRS_ASM_DISCOVERY_STRING=/dev/asm-disk*' \
        -e INIT_SGA_SIZE=3G -e INIT_PGA_SIZE=2G \
        -e DB_NAME=ORCLCDB -e ORACLE_PDB_NAME=ORCLPDB \
        "$rac_image"
done
podman start autodiag-rac1 autodiag-rac2
echo 'Lab started. Monitor installation; do not assume database readiness from container state.'
