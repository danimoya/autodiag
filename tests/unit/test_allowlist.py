"""Only named, validated commands can ever be executed on a database node."""

import pytest

from autodiag.transport.allowlist import (
    ALLOWLIST,
    AllowlistError,
    build_command,
    remote_shell_line,
)


def test_unknown_command_is_rejected() -> None:
    with pytest.raises(AllowlistError, match="unknown command"):
        build_command("rm_rf", {})


def test_adrci_show_problem_renders_single_exec_argument() -> None:
    argv = build_command("adrci_show_problem", {"adr_home": "diag/rdbms/free/FREE", "days": 7})
    assert argv[0] == "adrci"
    assert argv[1].startswith("exec=set home diag/rdbms/free/FREE;")
    assert "show problem" in argv[1]
    assert "systimestamp - 7" in argv[1]


@pytest.mark.parametrize(
    "bad_home",
    [
        "/opt/oracle/diag/rdbms/free/FREE",
        "diag/../../etc",
        "diag/rdbms/free/FREE; rm -rf /",
        'diag/rdbms/free/FREE"',
        "",
    ],
)
def test_adr_home_must_be_relative_and_clean(bad_home: str) -> None:
    with pytest.raises(AllowlistError):
        build_command("adrci_show_problem", {"adr_home": bad_home, "days": 1})


def test_missing_parameter_is_rejected() -> None:
    with pytest.raises(AllowlistError, match="missing parameter"):
        build_command("adrci_show_problem", {"adr_home": "diag/rdbms/free/FREE"})


def test_unexpected_parameter_is_rejected() -> None:
    with pytest.raises(AllowlistError, match="unexpected parameter"):
        build_command("hostname", {"extra": "x"})


def test_int_parameter_must_be_int() -> None:
    with pytest.raises(AllowlistError):
        build_command("adrci_show_problem", {"adr_home": "diag/rdbms/free/FREE", "days": "7; ls"})


def test_path_must_be_under_an_allowed_root() -> None:
    roots = ["/opt/oracle/diag"]
    ok = build_command(
        "read_range",
        {
            "path": "/opt/oracle/diag/rdbms/free/FREE/trace/alert_FREE.log",
            "offset": 0,
            "length": 100,
        },
        allowed_roots=roots,
    )
    assert ok[0] == "tail"
    with pytest.raises(AllowlistError, match="allowed root"):
        build_command(
            "read_range", {"path": "/etc/passwd", "offset": 0, "length": 100}, allowed_roots=roots
        )
    with pytest.raises(AllowlistError):
        build_command(
            "read_range",
            {"path": "/opt/oracle/diag/../../etc/passwd", "offset": 0, "length": 100},
            allowed_roots=roots,
        )


def test_path_without_roots_is_rejected() -> None:
    with pytest.raises(AllowlistError, match="allowed root"):
        build_command("stat_file", {"path": "/opt/oracle/diag/x"}, allowed_roots=[])


def test_problem_key_predicate_forbids_quotes() -> None:
    ok = build_command(
        "adrci_show_problem_by_key",
        {"adr_home": "diag/rdbms/free/FREE", "problem_key": "ORA 600 [autodiag_test]"},
    )
    assert "problem_key='ORA 600 [autodiag_test]'" in ok[1]
    for bad in ["ORA 600 [x]' or 1=1 --", 'ORA "600"', "ORA;600"]:
        with pytest.raises(AllowlistError):
            build_command(
                "adrci_show_problem_by_key",
                {"adr_home": "diag/rdbms/free/FREE", "problem_key": bad},
            )
    incidents = build_command(
        "adrci_show_incident",
        {"adr_home": "diag/rdbms/free/FREE", "problem_id": 3, "mode": "brief"},
    )
    assert "problem_id=3" in incidents[1]


def test_choice_parameter() -> None:
    with pytest.raises(AllowlistError, match="one of"):
        build_command(
            "adrci_show_incident",
            {"adr_home": "diag/rdbms/free/FREE", "problem_id": 1, "mode": "verbose"},
        )


def test_grep_pattern_is_passed_as_fixed_string_argument() -> None:
    argv = build_command(
        "grep_file",
        {
            "path": "/opt/oracle/diag/a.log",
            "pattern": "ORA-00060: Deadlock $(id)",
            "context": 2,
            "max_lines": 50,
        },
        allowed_roots=["/opt/oracle/diag"],
    )
    line = remote_shell_line(argv)
    # the pattern is a single quoted argument, so shell metacharacters are inert
    assert "'ORA-00060: Deadlock $(id)'" in line
    assert argv[:2] == ["grep", "-nF"]


def test_remote_shell_line_quotes_every_argument() -> None:
    line = remote_shell_line(["adrci", "exec=set home diag/rdbms/free/FREE; show problem"])
    assert line == "adrci 'exec=set home diag/rdbms/free/FREE; show problem'"


def test_every_spec_has_description_timeout_and_params_matching_template() -> None:
    for name, spec in ALLOWLIST.items():
        assert spec.description, name
        assert spec.timeout > 0, name
        placeholders = {p for arg in spec.argv for p in _placeholders(arg)}
        assert placeholders == set(spec.params), f"{name}: {placeholders} != {set(spec.params)}"


def _placeholders(template: str) -> list[str]:
    import string

    return [f for _, f, _, _ in string.Formatter().parse(template) if f]
