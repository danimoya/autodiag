from autodiag.core.redact import redact_for_llm


def test_bind_values_and_literals_are_masked() -> None:
    txt = (
        " Bind#0\n  oacdty=02 mxl=22(22) mxlc=00 mal=00 scl=00 pre=00\n  value=4711\n"
        "SELECT * FROM t WHERE name = 'Alice Smith' AND id = 12345 AND ip = '10.0.0.5'\n"
    )
    out = redact_for_llm(txt)
    assert "4711" not in out and "value=<redacted>" in out
    assert "Alice Smith" not in out and "'<str>'" in out
    assert "10.0.0.5" not in out
    assert "12345" in out  # bare numbers in SQL stay (they are rarely PII and often needed)


def test_hostnames_and_emails_are_masked() -> None:
    out = redact_for_llm("image: oracle@dbnode01.example.internal user bob@example.com")
    assert "dbnode01.example.internal" not in out
    assert "bob@example.com" not in out


def test_paths_and_ora_lines_are_kept() -> None:
    txt = (
        "Errors in file /u02/app/oracle/diag/rdbms/x/X/trace/X_ora_1.trc:\n"
        "ORA-00600: internal error code, arguments: [kglic0], [0]"
    )
    out = redact_for_llm(txt)
    assert "/u02/app/oracle/diag/rdbms/x/X/trace/X_ora_1.trc" in out
    assert "ORA-00600: internal error code, arguments: [kglic0], [0]" in out


def test_versions_are_not_mistaken_for_ips() -> None:
    out = redact_for_llm("Version 23.26.3.0.0 from 10.0.0.5 and 192.168.1.10.")
    assert "23.26.3.0.0" in out
    assert "10.0.0.5" not in out and "192.168.1.10" not in out


def test_disabled_is_identity() -> None:
    assert redact_for_llm("value=1 'x'", enabled=False) == "value=1 'x'"
