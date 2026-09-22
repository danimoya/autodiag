"""Named, read-only SQL queries shipped with AutoDiag (``sql/catalog/*.sql``).

Each file starts with a header of ``-- key: value`` lines::

    -- name: diag_problems
    -- desc: ADR problems with recent incidents
    -- scope: cdb | pdb        (pdb queries may switch container first)
    -- pack: none | diagnostics (diagnostics = needs the Diagnostics Pack)
    -- params: since_hours:int=168, sql_id:str

Only bind variables are used; there is no string interpolation into SQL.
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources

from pydantic import BaseModel, Field

_HEADER = re.compile(r"^--\s*(\w+):\s*(.*?)\s*$")
_BIND = re.compile(r"(?<![:\w]):([A-Za-z_]\w*)")
_PARAM = re.compile(r"^(\w+):(int|str|float)(?:=(.*))?$")


class ParamSpec(BaseModel):
    name: str
    type: str
    default: int | float | str | None = None

    def coerce(self, value: object) -> int | float | str:
        try:
            if self.type == "int":
                return int(value)  # type: ignore[arg-type]
            if self.type == "float":
                return float(value)  # type: ignore[arg-type]
            return str(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"parameter {self.name!r} must be {self.type}") from exc


class Query(BaseModel):
    name: str
    description: str
    scope: str = "cdb"
    pack: str = "none"
    params: dict[str, ParamSpec] = Field(default_factory=dict)
    sql: str

    @property
    def binds(self) -> list[str]:
        return sorted(set(_BIND.findall(self.sql)))

    def bind_values(self, params: dict[str, object]) -> dict[str, int | float | str]:
        unknown = set(params) - set(self.params)
        if unknown:
            raise ValueError(f"unknown parameter(s) {sorted(unknown)} for query {self.name!r}")
        out: dict[str, int | float | str] = {}
        for name, spec in self.params.items():
            if name in params:
                out[name] = spec.coerce(params[name])
            elif spec.default is not None:
                out[name] = spec.coerce(spec.default)
            else:
                raise ValueError(f"missing parameter {name!r} for query {self.name!r}")
        return out


def parse_query(text: str, *, fallback_name: str) -> Query:
    header: dict[str, str] = {}
    body: list[str] = []
    for line in text.splitlines():
        m = _HEADER.match(line)
        if m and not body:
            header[m.group(1).lower()] = m.group(2)
        else:
            body.append(line)
    params: dict[str, ParamSpec] = {}
    for part in filter(None, (p.strip() for p in header.get("params", "").split(","))):
        pm = _PARAM.match(part)
        if not pm:
            raise ValueError(f"bad param spec {part!r} in query {fallback_name}")
        spec = ParamSpec(name=pm.group(1), type=pm.group(2))
        if pm.group(3) is not None:
            spec.default = spec.coerce(pm.group(3))
        params[pm.group(1)] = spec
    return Query(
        name=header.get("name", fallback_name),
        description=header.get("desc", ""),
        scope=header.get("scope", "cdb"),
        pack=header.get("pack", "none"),
        params=params,
        sql="\n".join(body).strip(),
    )


@lru_cache
def load_catalog() -> dict[str, Query]:
    out: dict[str, Query] = {}
    root = resources.files("autodiag.sql").joinpath("catalog")
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".sql"):
            q = parse_query(entry.read_text(encoding="utf-8"), fallback_name=entry.name[:-4])
            out[q.name] = q
    return out
