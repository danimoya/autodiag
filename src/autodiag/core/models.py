"""Core data models shared by every layer (pydantic v2)."""

from __future__ import annotations

import os
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TargetKind(StrEnum):
    SINGLE = "single"
    RAC = "rac"


class Platform(StrEnum):
    GENERIC = "generic"
    EXACC = "exacc"


class Node(BaseModel):
    """One database host reachable over SSH."""

    model_config = ConfigDict(extra="forbid")

    host: str
    ssh_user: str = "oracle"
    ssh_alias: str | None = Field(default=None, description="ssh_config Host alias, if any")
    ssh_port: int = 22
    instance: str | None = Field(default=None, description="Instance name on this node")
    oracle_home: str | None = None

    @property
    def ssh_target(self) -> str:
        return self.ssh_alias or f"{self.ssh_user}@{self.host}"


class SqlNetConfig(BaseModel):
    """Read-only SQL*Net access. The password is never stored; it comes from the env."""

    model_config = ConfigDict(extra="forbid")

    dsn: str
    user: str
    password_env: str
    wallet_dir: str | None = None

    def password(self) -> str | None:
        return os.environ.get(self.password_env)

    def __repr__(self) -> str:  # never leak the password through repr/str
        return (
            f"SqlNetConfig(dsn={self.dsn!r}, user={self.user!r}, "
            f"password_env={self.password_env!r})"
        )


class Target(BaseModel):
    """A database (single instance or RAC) that AutoDiag can diagnose."""

    model_config = ConfigDict(extra="forbid")

    name: str
    kind: TargetKind = TargetKind.SINGLE
    platform: Platform = Platform.GENERIC
    oracle_version: str | None = None
    db_unique_name: str | None = None
    diagnostics_pack: bool = True
    nodes: list[Node] = Field(min_length=1)
    adr_base: str | None = Field(
        default=None, description="ADR base on the nodes, e.g. /u02/app/oracle"
    )
    adr_homes: list[str] = Field(default_factory=list, description="Relative ADR homes")
    sqlnet: SqlNetConfig | None = None
    extra_roots: list[str] = Field(
        default_factory=list,
        description="Additional absolute roots readable over SSH (AHF, OSWatcher)",
    )
    ips_dest: str = Field(
        default="/tmp", description="Directory on the nodes for generated IPS zips"
    )
    redact: bool = True

    @field_validator("adr_homes")
    @classmethod
    def _homes_relative(cls, v: list[str]) -> list[str]:
        for h in v:
            if h.startswith("/") or ".." in h.split("/"):
                raise ValueError(f"adr_home must be relative and clean: {h!r}")
        return v

    @property
    def allowed_roots(self) -> list[str]:
        roots = [f"{self.adr_base.rstrip('/')}/diag"] if self.adr_base else []
        return roots + list(self.extra_roots) + [self.ips_dest]

    def node_for_instance(self, instance: str) -> Node:
        for n in self.nodes:
            if n.instance == instance:
                return n
        raise KeyError(instance)
