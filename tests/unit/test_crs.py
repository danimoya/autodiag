import pytest

from autodiag.adr.source import AdrSource
from autodiag.alertlog.xml import parse_alert_xml
from autodiag.core.models import Node, Target
from autodiag.diagnose.rules import classify
from autodiag.transport.ssh import CommandResult, SshTransport


def test_crs_discovery_and_alert_collection(tmp_path):
    xml = '<msg time="2026-10-06T12:00:00+00:00" type="3"><txt>CRS failure</txt></msg>'

    class Transport:
        def run(self, name, params):
            return CommandResult(
                name=name, argv=[], returncode=0, stdout="diag/rdbms/db/DB1\ndiag/crs/node1/crs"
            )

        def fetch_tail(self, path, dest, **kw):
            assert path == "/u01/grid/diag/crs/node1/crs/alert/log.xml"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(xml)
            return CommandResult(name="tail", argv=[], returncode=0, stdout="")

    t = Target(name="crs", component="crs", adr_base="/u01/grid", nodes=[Node(host="node1")])
    src = AdrSource(t, transport_factory=lambda node: Transport())
    assert src.refs()[0][1] == "diag/crs/node1/crs"
    result = src.read_alert(t.nodes[0], "diag/crs/node1/crs", tmp_path)
    assert result.records[0].text == "CRS failure"
    assert classify(result.records[0]).severity == "warning"
    assert src.alert_log_path(t.nodes[0], "diag/crs/node1/crs").endswith("/trace/alert.log")
    assert parse_alert_xml(xml)[0].ts is not None


def test_sudo_and_explicit_adr_base():
    node = Node(host="db", sudo_user="grid", adr_base="/u01/app/grid")
    transport = SshTransport(node, ["/u01/app/grid/diag"])
    cmd = transport.remote_command(["adrci", "exec=show homes"])
    assert cmd.startswith("sudo -n -u grid -- bash -lc")
    assert "cd / || exit 1" in cmd
    assert "set base /u01/app/grid; show homes" in cmd
    node.adr_base = "/u01;host id"
    with pytest.raises(ValueError):
        transport.remote_command(["adrci", "exec=show homes"])


def test_xml_error_does_not_downgrade_critical_database_fault():
    xml = '<msg time="2026-10-06T12:00:00+00:00" type="3"><txt>ORA-00600: error</txt></msg>'
    assert classify(parse_alert_xml(xml)[0]).severity == "critical"


def test_asm_homes_mapped_to_instance_and_case_insensitive():
    target = Target(
        name="asm",
        component="asm",
        adr_base="/u01/grid",
        nodes=[Node(host="node1", instance="+ASM1"), Node(host="node2", instance="+ASM2")],
        adr_homes=["diag/asm/+asm/+asm1", "diag/asm/+asm/+asm2"],
    )
    source = AdrSource(target)
    assert [(node.host, home) for node, home in source.refs()] == [
        ("node1", "diag/asm/+asm/+asm1"),
        ("node2", "diag/asm/+asm/+asm2"),
    ]
    assert source.alert_log_path(target.nodes[0], target.adr_homes[0]).endswith(
        "/trace/alert_+ASM1.log"
    )


@pytest.mark.parametrize(
    "component,home", [("crs", "diag/crs/node1/crs"), ("asm", "diag/asm/+asm/+ASM1")]
)
def test_alert_paths_use_node_adr_base(component, home):
    node = Node(host="node1", adr_base="/different/grid/")
    source = AdrSource(
        Target(
            name="grid",
            component=component,
            adr_base="/default/grid",
            nodes=[node],
            adr_homes=[home],
        )
    )
    assert source.alert_log_path(node, home).startswith("/different/grid/diag/")
    assert source.alert_xml_path(node, home).startswith("/different/grid/diag/")


def test_grouped_crs_homes_are_resolved_on_each_node():
    homes = ["diag/crs/node1/crs", "diag/crs/node2/crs"]

    class Transport:
        def __init__(self, node):
            self.node = node

        def run(self, name, params):
            assert name == "adrci_show_homes"
            return CommandResult(
                name=name, argv=[], returncode=0, stdout=f"diag/crs/{self.node.instance}/crs"
            )

    nodes = [Node(host="alias-one", instance="node1"), Node(host="alias-two", instance="node2")]
    source = AdrSource(
        Target(name="cluster", component="crs", nodes=nodes, adr_homes=homes),
        transport_factory=Transport,
    )
    assert [(n.host, h) for n, h in source.refs()] == list(
        zip([n.host for n in nodes], homes, strict=True)
    )


def test_node_specific_file_allowlist():
    from autodiag.transport.allowlist import AllowlistError, build_command

    node = Node(host="node2", adr_base="/custom/grid")
    target = Target(name="cluster", nodes=[node], adr_base="/default/grid")
    transport = AdrSource(target).transport_for(node)
    build_command(
        "cat_file",
        {"path": "/custom/grid/diag/crs/node2/crs/trace/alert.log"},
        allowed_roots=transport.allowed_roots,
    )
    with pytest.raises(AllowlistError):
        build_command(
            "cat_file",
            {"path": "/default/grid/diag/crs/node1/crs/trace/alert.log"},
            allowed_roots=transport.allowed_roots,
        )


def test_adrci_zero_exit_does_not_hide_diagnostic_errors():
    from autodiag.adr.source import AdrSourceError

    class Transport:
        def run(self, name, params):
            return CommandResult(
                name=name,
                argv=[],
                returncode=0,
                stdout="DIA-49450: Non-zero return code from archiving utility [127]",
            )

    node = Node(host="node1")
    source = AdrSource(Target(name="grid", nodes=[node]), transport_factory=lambda n: Transport())
    with pytest.raises(AdrSourceError, match="DIA-49450"):
        source._run(node, "adrci_ips_generate", {})


@pytest.mark.parametrize(
    "field,value",
    [
        ("adr_base", "/other/base"),
        ("sudo_user", "otherowner"),
        ("oracle_home", "/other/home"),
        ("instance", "+ASM2"),
        ("ssh_port", 2222),
    ],
)
def test_transport_cache_isolates_execution_context(field, value):
    node = Node(host="node1", sudo_user="grid", instance="+ASM1", adr_base="/grid")
    source = AdrSource(Target(name="asm", nodes=[node]))
    first = source.transport_for(node)
    other = node.model_copy(update={field: value})
    assert source.transport_for(other) is not first
    assert source.transport_for(node.model_copy()) is first


@pytest.mark.parametrize("name", ["adrci_show_incident", "adrci_show_incident_by_id"])
def test_incident_payload_codes_are_not_command_failures(name):
    class Transport:
        def run(self, name, params):
            return CommandResult(
                name=name,
                argv=[],
                returncode=0,
                stdout="Incident detail\nDIA-12345: recorded historical error",
            )

    node = Node(host="node1")
    source = AdrSource(Target(name="db", nodes=[node]), transport_factory=lambda n: Transport())
    assert "DIA-12345" in source._run(node, name, {})


def test_adrci_stderr_zero_exit_is_failure():
    from autodiag.adr.source import AdrSourceError

    class Transport:
        def run(self, name, params):
            return CommandResult(
                name=name, argv=[], returncode=0, stdout="", stderr="DIA-49450: archive failure"
            )

    node = Node(host="node1")
    source = AdrSource(Target(name="db", nodes=[node]), transport_factory=lambda n: Transport())
    with pytest.raises(AdrSourceError, match="DIA-49450"):
        source._run(node, "adrci_ips_generate", {})


@pytest.mark.parametrize("rc,timeout", [(1, False), (2, False), (1, True)])
def test_grep_exit_status(rc, timeout):
    from autodiag.adr.source import AdrSourceError

    class Transport:
        def run(self, name, params):
            return CommandResult(name=name, argv=[], returncode=rc, stdout="", timed_out=timeout)

    node = Node(host="node1")
    source = AdrSource(Target(name="db", nodes=[node]), transport_factory=lambda n: Transport())
    if rc == 1 and not timeout:
        assert source.grep_file(node, "/grid/diag/alert.log", "absent") == ""
    else:
        with pytest.raises(AdrSourceError):
            source.grep_file(node, "/grid/diag/alert.log", "absent")


def test_xml_arguments_quotes_entities_and_attribute_greater_than():
    xml = """<msg time="2026-10-07T12:00:00+00:00" prob_key="x > y"><txt>hello</txt>
    <arg value="a &amp; b > c" name="first"/>
    <arg name='second' value='d &lt; e'/></msg>"""
    record = parse_alert_xml(xml)[0]
    assert record.problem_key == "x > y" and record.text == "hello"
    assert record.args == {"first": "a & b > c", "second": "d < e"}
