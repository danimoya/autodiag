"""Explicit-host discovery; no network scanning or remote configuration changes."""

import json
import re
import subprocess
from pathlib import Path

from autodiag.core.models import Node, Target


def discover(host: str, *, ssh_config: Path | None = None, timeout: int = 180) -> tuple:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]*", host):
        raise ValueError("host must be an SSH alias or [user@]hostname")
    argv = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=yes",
    ]
    if ssh_config:
        argv += ["-F", str(ssh_config)]
    argv += [host, "sudo -n -- python3 -"]
    script = Path(__file__).with_name("discovery_probe.py").read_text()
    try:
        result = subprocess.run(
            argv, input=script, capture_output=True, text=True, timeout=timeout, check=True
        )
    except subprocess.CalledProcessError as exc:
        raise ValueError(
            f"SSH/sudo discovery failed (exit {exc.returncode}); verify "
            "the host key, passwordless SSH, sudo -n, and remote python3"
        ) from None
    try:
        data = json.loads(result.stdout)
        if not isinstance(data, dict) or not isinstance(data.get("instances"), list):
            raise ValueError("invalid discovery structure")
    except (ValueError, TypeError):
        raise ValueError(
            "Discovery returned invalid JSON; check remote login banners and probe output"
        ) from None
    targets = []
    for item in data["instances"]:
        suffix = item["instance"] or item["component"]
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{data['hostname']}-{suffix}")
        targets.append(
            Target(
                name=name,
                component=item["component"],
                oracle_version=item.get("version"),
                nodes=[
                    Node(
                        host=data["hostname"],
                        ssh_alias=host,
                        sudo_user=item["owner"],
                        instance=item["instance"],
                        oracle_home=item["oracle_home"],
                        adr_base=item["adr_base"],
                    )
                ],
                adr_base=item["adr_base"],
                adr_homes=item["adr_homes"],
                diagnostics_pack=False,
            )
        )
    return targets, data.get("warnings", [])
