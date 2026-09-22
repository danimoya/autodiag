"""ADR access for one target over its nodes' transports (SSH today, SQL*Net later)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel

from autodiag.adr.adrci import (
    AdrIncident,
    AdrProblem,
    parse_show_homes,
    parse_show_incident,
    parse_show_problem,
)
from autodiag.core.models import Node, Target
from autodiag.transport.ssh import SshTransport


class ProblemRow(AdrProblem):
    node: str
    instance: str | None = None


class IncidentRow(AdrIncident):
    node: str
    instance: str | None = None


class AdrSourceError(RuntimeError):
    pass


class _Ref(BaseModel):
    node: Node
    adr_home: str


class AdrSource:
    def __init__(
        self,
        target: Target,
        *,
        transport_factory: Callable[[Node], object] | None = None,
        ssh_config: Path | None = None,
        connect_timeout: int = 10,
    ) -> None:
        self.target = target
        self._factory = transport_factory or (
            lambda node: SshTransport(
                node, target.allowed_roots, ssh_config=ssh_config, connect_timeout=connect_timeout
            )
        )
        self._transports: dict[str, object] = {}

    # -- plumbing --------------------------------------------------------------------
    def transport_for(self, node: Node):
        key = node.ssh_target
        if key not in self._transports:
            self._transports[key] = self._factory(node)
        return self._transports[key]

    def _run(self, node: Node, name: str, params: dict) -> str:
        res = self.transport_for(node).run(name, params)
        if not res.ok:
            raise AdrSourceError(
                f"{name} on {node.host} failed (rc={res.returncode}): {res.stderr.strip()[:300]}"
            )
        return res.stdout

    def _refs(self) -> list[_Ref]:
        refs: list[_Ref] = []
        for node in self.target.nodes:
            homes = self.target.adr_homes or self.list_homes(node)
            for home in homes:
                if (
                    node.instance
                    and not home.endswith("/" + node.instance)
                    and len(self.target.nodes) > 1
                ):
                    continue  # on RAC each node owns its own instance home
                refs.append(_Ref(node=node, adr_home=home))
        return refs

    def refs(self) -> list[tuple[Node, str]]:
        """(node, adr_home) pairs this target is diagnosed through, one per instance."""
        return [(r.node, r.adr_home) for r in self._refs()]

    # -- queries ---------------------------------------------------------------------
    def list_homes(self, node: Node) -> list[str]:
        homes = parse_show_homes(self._run(node, "adrci_show_homes", {}))
        return [h for h in homes if h.startswith("diag/rdbms/")]

    def list_problems(self, days: int = 7) -> list[ProblemRow]:
        out: list[ProblemRow] = []
        for ref in self._refs():
            text = self._run(
                ref.node, "adrci_show_problem", {"adr_home": ref.adr_home, "days": days}
            )
            for p in parse_show_problem(text):
                out.append(
                    ProblemRow(**p.model_dump(), node=ref.node.host, instance=ref.node.instance)
                )
        out.sort(key=lambda p: (p.lastinc_time is None, p.lastinc_time), reverse=True)
        return out

    def list_incidents(
        self, *, problem_id: int | None = None, problem_key: str | None = None, mode: str = "brief"
    ) -> list[IncidentRow]:
        """Incidents of one problem. adrci filters incidents by ``problem_id`` only, so a key
        is first resolved to the matching problem id(s) through ``show problem``."""
        if problem_id is None and problem_key is None:
            raise AdrSourceError("problem_id or problem_key is required")
        out: list[IncidentRow] = []
        for ref in self._refs():
            ids = (
                [problem_id]
                if problem_id is not None
                else self._problem_ids_for_key(ref, problem_key or "")
            )
            for pid in ids:
                text = self._run(
                    ref.node,
                    "adrci_show_incident",
                    {"adr_home": ref.adr_home, "problem_id": pid, "mode": mode},
                )
                for i in parse_show_incident(text):
                    out.append(
                        IncidentRow(
                            **i.model_dump(), node=ref.node.host, instance=ref.node.instance
                        )
                    )
        out.sort(key=lambda i: i.incident_id, reverse=True)
        return out

    def _problem_ids_for_key(self, ref: _Ref, problem_key: str) -> list[int]:
        text = self._run(
            ref.node,
            "adrci_show_problem_by_key",
            {"adr_home": ref.adr_home, "problem_key": problem_key},
        )
        return [p.problem_id for p in parse_show_problem(text)]

    def get_incident(self, incident_id: int) -> IncidentRow | None:
        for ref in self._refs():
            text = self._run(
                ref.node,
                "adrci_show_incident_by_id",
                {"adr_home": ref.adr_home, "incident_id": incident_id, "mode": "detail"},
            )
            incs = parse_show_incident(text)
            if incs:
                return IncidentRow(
                    **incs[0].model_dump(), node=ref.node.host, instance=ref.node.instance
                )
        return None

    # -- files -----------------------------------------------------------------------
    def alert_log_path(self, node: Node, adr_home: str) -> str:
        base = (self.target.adr_base or "").rstrip("/")
        instance = node.instance or adr_home.rsplit("/", 1)[-1]
        return f"{base}/{adr_home}/trace/alert_{instance}.log"

    def alert_xml_path(self, node: Node, adr_home: str) -> str:
        base = (self.target.adr_base or "").rstrip("/")
        return f"{base}/{adr_home}/alert/log.xml"

    def fetch_file(
        self, node: Node, path: str, dest: Path, *, max_bytes: int | None = None
    ) -> Path:
        res = self.transport_for(node).fetch(path, dest, max_bytes=max_bytes)
        if res.returncode != 0:
            raise AdrSourceError(f"fetch {path} failed: {res.stderr[:200]}")
        return dest

    def grep_file(
        self, node: Node, path: str, pattern: str, *, context: int = 3, max_lines: int = 200
    ) -> str:
        return self._run(
            node,
            "grep_file",
            {"path": path, "pattern": pattern, "context": context, "max_lines": max_lines},
        )

    def primary_ref(self) -> tuple[Node, str]:
        refs = self._refs()
        if not refs:
            raise AdrSourceError("target has no ADR homes")
        return refs[0].node, refs[0].adr_home
