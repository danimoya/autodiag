from autodiag.core.models import Node, Target
from autodiag.report.env import capture_environment, parse_opatch_lspatches
from autodiag.sql.runner import QueryResult
from autodiag.transport.ssh import CommandResult

OPATCH = """Oracle Interim Patch Installer version 12.2.0.1.42
Copyright (c) 2024, Oracle Corporation.  All rights reserved.

36582781;Database Release Update : 19.24.0.0.240716 (36582781)
36414915;OJVM RELEASE UPDATE: 19.24.0.0.240716 (36414915)
29585399;OCW RELEASE UPDATE 19.3.0.0.0 (29585399)

OPatch succeeded.
"""


def test_parse_opatch() -> None:
    patches = parse_opatch_lspatches(OPATCH)
    assert patches[0] == {
        "id": "36582781",
        "description": "Database Release Update : 19.24.0.0.240716",
    }
    assert len(patches) == 3


class FakeTransport:
    def __init__(self, node):
        self.node = node

    def run(self, name, params, **kw):
        out = {
            "hostname": "dbnode01\n",
            "uptime": " 12:00 up 40 days\n",
            "opatch_lspatches": OPATCH,
        }.get(name, "")
        return CommandResult(name=name, argv=[name], returncode=0, stdout=out)


class FakeRunner:
    def run_named(self, name, params=None, *, max_rows=200, container=None):
        if name == "db_info":
            return QueryResult(
                name=name,
                columns=[
                    "DB_NAME",
                    "DB_UNIQUE_NAME",
                    "VERSION_FULL",
                    "INSTANCE_NAME",
                    "HOST_NAME",
                    "STARTUP_TIME",
                    "DATABASE_ROLE",
                ],
                rows=[
                    ["FREE", "FREE", "23.26.3.0.0", "FREE", "oradb-test", "2026-09-22", "PRIMARY"]
                ],
            )
        if name == "sqlpatch_registry":
            return QueryResult(
                name=name,
                columns=[
                    "PATCH_ID",
                    "PATCH_TYPE",
                    "ACTION",
                    "STATUS",
                    "ACTION_TIME",
                    "DESCRIPTION",
                ],
                rows=[
                    [
                        36582781,
                        "RU",
                        "APPLY",
                        "SUCCESS",
                        "2026-01-01",
                        "Database Release Update : 19.24",
                    ]
                ],
            )
        if name == "params_nondefault":
            return QueryResult(
                name=name,
                columns=["NAME", "VALUE", "ISMODIFIED", "ISDEFAULT"],
                rows=[["sga_target", "8G", "FALSE", "FALSE"]],
            )
        if name == "rac_instances":
            return QueryResult(
                name=name,
                columns=["INST_ID", "INSTANCE_NAME", "HOST_NAME", "STATUS"],
                rows=[[1, "FREE", "oradb-test", "OPEN"]],
            )
        raise AssertionError(name)


def test_capture_environment_merges_sources() -> None:
    t = Target(
        name="tb",
        nodes=[Node(host="h", oracle_home="/u01/app/oracle/product/19/dbhome_1")],
        adr_base="/opt/oracle",
    )
    env = capture_environment(t, transport_factory=FakeTransport, runner=FakeRunner())
    assert env["version_full"] == "23.26.3.0.0" and env["db_unique_name"] == "FREE"
    assert env["patches"][0].startswith("36582781 Database Release Update")
    assert env["sqlpatch"][0]["PATCH_ID"] == 36582781
    assert env["nondefault_parameters"] == {"sga_target": "8G"}
    assert env["nodes"][0]["hostname"] == "dbnode01" and "40 days" in env["nodes"][0]["uptime"]
    assert env["instances"][0]["INSTANCE_NAME"] == "FREE"
    assert env["errors"] == []


def test_capture_environment_tolerates_missing_sources() -> None:
    t = Target(name="tb", nodes=[Node(host="h")])
    env = capture_environment(t, transport_factory=None, runner=None)
    assert env["patches"] == [] and env["nodes"] == [] and "no SQL*Net" in " ".join(env["errors"])
