import os
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("output", "code", "expect_setup", "expect_ok"),
    [
        ("\\t 0\\n", 0, True, True),
        ("\\t 1\\n", 0, False, True),
        ("invalid\\n", 0, False, False),
        ("", 1, False, False),
    ],
)
def test_startup_schema_probe(tmp_path, output, code, expect_setup, expect_ok):
    root = Path(__file__).resolve().parents[2]
    oracle_home = tmp_path / "oracle"
    (oracle_home / "bin").mkdir(parents=True)
    sqlplus = oracle_home / "bin" / "sqlplus"
    sqlplus.write_text(f"#!/bin/bash\nprintf '{output}'\nexit {code}\n")
    sqlplus.chmod(0o700)
    setup = tmp_path / "setup.sh"
    setup.write_text("#!/bin/bash\necho SETUP_INVOKED\n")
    setup.chmod(0o700)
    script = (
        (root / "testbed/sshd/02_autodiag_setup.sh")
        .read_text()
        .replace("/opt/oracle/scripts/setup/01_users.sh", str(setup))
    )
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        env={**os.environ, "ORACLE_HOME": str(oracle_home), "AUTODIAG_ENABLE_ORADEBUG": "false"},
    )
    assert (result.returncode == 0) == expect_ok
    assert ("SETUP_INVOKED" in result.stdout) == expect_setup


def test_fault_incident_delta_handles_different_id_widths(tmp_path):
    root = Path(__file__).resolve().parents[2]
    faults = tmp_path / "faults"
    faults.mkdir()
    helper = faults / "_lib.sh"
    helper.write_text((root / "testbed/faults/_lib.sh").read_text())
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; tb_new_ids "$2" "$3"',
            "test",
            str(helper),
            "9\n10\n10000",
            "9\n10\n11\n10000\n10001",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "AUTODIAG_FAULT_OUT": str(tmp_path / "out")},
    )
    assert result.returncode == 0 and not result.stderr
    assert result.stdout.strip() == "11 10001"
