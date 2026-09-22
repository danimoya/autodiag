"""Runs catalog queries over SQL*Net with python-oracledb (thin mode, no client needed)."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

from autodiag.core.models import SqlNetConfig
from autodiag.sql.catalog import Query, load_catalog

_CONTAINER = re.compile(r"^[A-Za-z0-9_$#]{1,30}$")


class SqlRunnerError(RuntimeError):
    pass


class QueryResult(BaseModel):
    name: str
    columns: list[str]
    rows: list[list[Any]]
    truncated: bool = False
    elapsed_ms: int = 0
    container: str | None = None
    binds: dict[str, Any] = Field(default_factory=dict)

    def as_dicts(self) -> list[dict[str, Any]]:
        return [dict(zip(self.columns, r, strict=False)) for r in self.rows]


def _default_connect(**kw: Any):
    import oracledb  # imported lazily so the core has no hard runtime dependency

    return oracledb.connect(**kw)


class SqlRunner:
    def __init__(
        self,
        sqlnet: SqlNetConfig,
        *,
        timeout: int = 60,
        diagnostics_pack: bool = True,
        connect: Callable[..., Any] = _default_connect,
    ) -> None:
        self.sqlnet = sqlnet
        self.timeout = timeout
        self.diagnostics_pack = diagnostics_pack
        self._connect = connect

    def query(self, name: str) -> Query:
        q = load_catalog().get(name)
        if q is None:
            raise SqlRunnerError(f"unknown query {name!r}")
        return q

    def run_named(
        self,
        name: str,
        params: dict[str, object] | None = None,
        *,
        max_rows: int = 200,
        container: str | None = None,
    ) -> QueryResult:
        q = self.query(name)
        if q.pack == "diagnostics" and not self.diagnostics_pack:
            raise SqlRunnerError(
                f"query {name!r} needs the Diagnostics Pack, disabled for this target"
            )
        try:
            binds = q.bind_values(params or {})
        except ValueError as exc:
            raise SqlRunnerError(str(exc)) from exc
        if container is not None and not _CONTAINER.match(container):
            raise SqlRunnerError(f"invalid container name {container!r}")
        password = self.sqlnet.password()
        if not password:
            raise SqlRunnerError(
                f"no password for {self.sqlnet.user}: "
                f"set ${self.sqlnet.password_env} in the secrets file"
            )
        started = time.monotonic()
        conn = self._connect(user=self.sqlnet.user, password=password, dsn=self.sqlnet.dsn)
        try:
            try:
                conn.call_timeout = self.timeout * 1000
            except AttributeError:
                pass
            cur = conn.cursor()
            try:
                used_container = None
                if q.scope == "pdb" and container:
                    cur.execute(f'ALTER SESSION SET CONTAINER = "{container}"')
                    used_container = container
                cur.execute(q.sql, binds)
                columns = [d[0] for d in (cur.description or [])]
                rows = [list(r) for r in cur.fetchmany(max_rows + 1)]
                truncated = len(rows) > max_rows
                return QueryResult(
                    name=name,
                    columns=columns,
                    rows=rows[:max_rows],
                    truncated=truncated,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    container=used_container,
                    binds=binds,
                )
            finally:
                cur.close()
        finally:
            conn.close()

    def ping(self) -> dict[str, Any]:
        res = self.run_named("db_info", {}, max_rows=5)
        return res.as_dicts()[0] if res.rows else {}
