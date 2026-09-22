import pytest

from autodiag.core.models import SqlNetConfig
from autodiag.sql.runner import SqlRunner, SqlRunnerError


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = None
        self._rows = []

    def execute(self, sql, binds=None):
        self.conn.executed.append((sql, binds))
        if sql.upper().startswith("SELECT"):
            self.description = [("NAME",), ("VALUE",)]
            self._rows = [("a", 1), ("b", 2), ("c", 3)]
        else:
            self.description = None
            self._rows = []

    def fetchmany(self, n):
        out, self._rows = self._rows[:n], self._rows[n:]
        return out

    def close(self):
        pass


class FakeConn:
    def __init__(self):
        self.executed = []
        self.call_timeout = None
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def close(self):
        self.closed = True


@pytest.fixture
def cfg(monkeypatch) -> SqlNetConfig:
    monkeypatch.setenv("TB_PWD", "secret")
    return SqlNetConfig(dsn="127.0.0.1:1521/FREEPDB1", user="c##autodiag", password_env="TB_PWD")


def test_run_named_binds_and_caps_rows(cfg) -> None:
    conn = FakeConn()
    r = SqlRunner(cfg, connect=lambda **kw: conn, timeout=7)
    res = r.run_named("diag_problems", {"since_hours": 24}, max_rows=2)
    assert res.columns == ["NAME", "VALUE"] and res.rows == [["a", 1], ["b", 2]] and res.truncated
    sql, binds = conn.executed[-1]
    assert binds == {"since_hours": 24} and ":since_hours" in sql
    assert conn.call_timeout == 7000 and conn.closed


def test_pdb_scope_switches_container_only_when_asked(cfg) -> None:
    conn = FakeConn()
    r = SqlRunner(cfg, connect=lambda **kw: conn)
    r.run_named("sessions_active_now", {}, container="FREEPDB1")
    assert conn.executed[0][0] == 'ALTER SESSION SET CONTAINER = "FREEPDB1"'
    conn2 = FakeConn()
    SqlRunner(cfg, connect=lambda **kw: conn2).run_named("diag_problems", {}, container="FREEPDB1")
    assert not any("CONTAINER" in s for s, _ in conn2.executed)  # cdb-scoped query ignores it


def test_unknown_query_and_missing_password(cfg, monkeypatch) -> None:
    r = SqlRunner(cfg, connect=lambda **kw: FakeConn())
    with pytest.raises(SqlRunnerError, match="unknown query"):
        r.run_named("drop_everything", {})
    monkeypatch.delenv("TB_PWD")
    with pytest.raises(SqlRunnerError, match="password"):
        SqlRunner(cfg, connect=lambda **kw: FakeConn()).run_named("db_info", {})


def test_container_name_is_validated(cfg) -> None:
    r = SqlRunner(cfg, connect=lambda **kw: FakeConn())
    with pytest.raises(SqlRunnerError, match="container"):
        r.run_named("sessions_active_now", {}, container='X"; drop user')


def test_diagnostics_pack_gate(cfg) -> None:
    r = SqlRunner(cfg, connect=lambda **kw: FakeConn(), diagnostics_pack=False)
    with pytest.raises(SqlRunnerError, match="Diagnostics Pack"):
        r.run_named(
            "ash_top_sql_window", {"from_ts": "2026-01-01 00:00:00", "to_ts": "2026-01-01 01:00:00"}
        )
