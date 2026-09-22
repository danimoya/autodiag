"""Integration tests run against the testbed container described in docs/testbed.md.

They are selected with ``pytest -m integration`` and skipped when the ``testbed`` target
is missing from the inventory or unreachable.
"""

import subprocess

import pytest

from autodiag.adr.source import AdrSource
from autodiag.cli import common
from autodiag.core.settings import load_settings


@pytest.fixture(scope="session")
def testbed_source() -> AdrSource:
    s = load_settings()
    try:
        t = common.inventory(s).get("testbed")
    except KeyError:
        pytest.skip("no 'testbed' target in the inventory")
    probe = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            *(["-F", str(s.ssh_config)] if s.ssh_config else []),
            t.nodes[0].ssh_target,
            "true",
        ],
        capture_output=True,
    )
    if probe.returncode != 0:
        pytest.skip("testbed not reachable over ssh")
    return common.source(t, s)
