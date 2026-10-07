"""Opt-in read-only checks against an already configured two-node RAC lab."""

import os
from pathlib import Path

import pytest

from autodiag.adr.source import AdrSource
from autodiag.core.discovery import discover

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("alias", ["autodiag-rac1", "autodiag-rac2"])
def test_running_crs_asm_database_discovery_and_adr(alias, tmp_path):
    configured = os.environ.get("AUTODIAG_RAC_SSH_CONFIG")
    if not configured:
        pytest.skip("Set AUTODIAG_RAC_SSH_CONFIG to the verified RAC lab SSH config")
    ssh_config = Path(configured)
    targets, warnings = discover(alias, ssh_config=ssh_config)
    assert not warnings
    assert {t.component for t in targets} == {"crs", "asm", "rdbms"}
    for target in targets:
        assert target.nodes[0].sudo_user == ("oracle" if target.component == "rdbms" else "grid")
        source = AdrSource(target, ssh_config=ssh_config)
        assert set(target.adr_homes) <= set(source.list_homes(target.nodes[0]))
        source.list_problems(days=1)  # no error is expected, even if there are no problems
        # An absent ID exercises the actual ADRCI incident query on all components
        # without generating artificial Oracle faults or claiming extraction coverage.
        assert source.get_incident(2147483647) is None
        assert source.list_incidents(problem_id=2147483647) == []
        for node, home in source.refs():
            assert (
                source.grep_file(
                    node, source.alert_log_path(node, home), "AUTODIAG_ABSENT_98f65eaa8"
                )
                == ""
            )
            assert source.grep_file(node, source.alert_log_path(node, home), "2026", max_lines=1)
            alert = source.read_alert(node, home, tmp_path / target.name)
            assert alert.records, f"No parsed alert records for {target.name}"


def test_grouped_crs_adr_reads(tmp_path):
    configured = os.environ.get("AUTODIAG_RAC_SSH_CONFIG")
    if not configured:
        pytest.skip("Set AUTODIAG_RAC_SSH_CONFIG to the verified RAC lab SSH config")
    ssh_config = Path(configured)
    crs = []
    for alias in ("autodiag-rac1", "autodiag-rac2"):
        targets, warnings = discover(alias, ssh_config=ssh_config)
        assert not warnings
        crs.append(next(t for t in targets if t.component == "crs"))
    grouped = crs[0].model_copy(
        update={
            "nodes": [t.nodes[0] for t in crs],
            "adr_homes": [h for t in crs for h in t.adr_homes],
        }
    )
    source = AdrSource(grouped, ssh_config=ssh_config)
    refs = source.refs()
    assert len(refs) == 2
    for node, home in refs:
        assert home in next(t.adr_homes for t in crs if t.nodes[0].host == node.host)
        assert source.read_alert(node, home, tmp_path).records
