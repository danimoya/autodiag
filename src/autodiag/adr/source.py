"""ADR access for one target over its nodes' transports (SSH today, SQL*Net later)."""

from __future__ import annotations

from collections.abc import Callable
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel

from autodiag.adr.adrci import (
    AdrIncident,
    AdrProblem,
    parse_show_homes,
    parse_show_incident,
    parse_show_problem,
)
from autodiag.alertlog.models import AlertRecord
from autodiag.alertlog.text import parse_alert_text
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


class AlertRead(BaseModel):
    records: list[AlertRecord]
    truncated: bool
    limit_bytes: int

    @property
    def coverage(self) -> dict:
        timestamps = [r.ts for r in self.records if r.ts]
        return {
            "truncated": self.truncated,
            "limit_bytes": self.limit_bytes,
            "oldest_available": min(timestamps).isoformat() if timestamps else None,
            "newest_available": max(timestamps).isoformat() if timestamps else None,
            "line_numbers": "tail-relative" if self.truncated else "file-relative",
            "warning": (
                f"Only the last {self.limit_bytes} bytes of the alert log were collected; "
                "Older history was omitted. Requested windows and rate comparisons "
                "may be incomplete."
                if self.truncated
                else None
            ),
        }


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

    def selected_refs(self, node: str | None = None, adr_home: str | None = None) -> list[_Ref]:
        refs = [
            r
            for r in self._refs()
            if (node is None or node in (r.node.host, r.node.ssh_alias, r.node.instance))
            and (adr_home is None or r.adr_home == adr_home)
        ]
        if not refs and (node is not None or adr_home is not None):
            raise AdrSourceError("No matching node/ADR home in this target")
        return refs

    def select_ref(self, node: str | None = None, adr_home: str | None = None) -> tuple[Node, str]:
        refs = self.selected_refs(node, adr_home)
        if len(refs) != 1:
            raise AdrSourceError("Select one ADR home with node and adr_home")
        return refs[0].node, refs[0].adr_home

    def incident_node(self, incident: IncidentRow) -> Node:
        return self.select_ref(incident.node, incident.adr_home)[0]

    @staticmethod
    def cache_path(cache: Path, node: Node, remote_path: str) -> Path:
        identity = sha256(f"{node.ssh_target}:{remote_path}".encode()).hexdigest()[:16]
        return cache / identity / Path(remote_path).name

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
                    ProblemRow(
                        **{**p.model_dump(), "adr_home": ref.adr_home},
                        node=ref.node.host,
                        instance=ref.node.instance,
                    )
                )
        out.sort(key=lambda p: (p.lastinc_time is None, p.lastinc_time), reverse=True)
        return out

    def list_incidents(
        self,
        *,
        problem_id: int | None = None,
        problem_key: str | None = None,
        mode: str = "brief",
        node: str | None = None,
        adr_home: str | None = None,
    ) -> list[IncidentRow]:
        """Incidents of one problem. adrci filters incidents by ``problem_id`` only, so a key
        is first resolved to the matching problem id(s) through ``show problem``."""
        if problem_id is None and problem_key is None:
            raise AdrSourceError("problem_id or problem_key is required")
        out: list[IncidentRow] = []
        for ref in self.selected_refs(node, adr_home):
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
                            **{**i.model_dump(), "adr_home": ref.adr_home},
                            node=ref.node.host,
                            instance=ref.node.instance,
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

    def get_incident(
        self, incident_id: int, *, node: str | None = None, adr_home: str | None = None
    ) -> IncidentRow | None:
        matches = []
        for ref in self.selected_refs(node, adr_home):
            text = self._run(
                ref.node,
                "adrci_show_incident_by_id",
                {"adr_home": ref.adr_home, "incident_id": incident_id, "mode": "detail"},
            )
            incs = parse_show_incident(text)
            if incs:
                matches.append(
                    IncidentRow(
                        **{**incs[0].model_dump(), "adr_home": ref.adr_home},
                        node=ref.node.host,
                        instance=ref.node.instance,
                    )
                )
        if len(matches) > 1:
            raise AdrSourceError(f"Incident {incident_id} is ambiguous; specify node and adr_home")
        return matches[0] if matches else None

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
        if not res.ok:
            raise AdrSourceError(f"fetch {path} failed: {res.stderr[:200]}")
        if res.truncated:
            raise AdrSourceError(
                f"fetch {path} was truncated; refusing to use an incomplete artifact"
            )
        return dest

    def read_alert(
        self, node: Node, home: str, cache: Path, *, max_bytes: int = 64 * 1024 * 1024
    ) -> AlertRead:
        path = self.alert_log_path(node, home)
        dest = self.cache_path(cache, node, path)
        res = self.transport_for(node).fetch_tail(path, dest, max_bytes=max_bytes)
        if not res.ok:
            raise AdrSourceError(f"alert tail fetch failed: {res.stderr[:200]}")
        records = parse_alert_text(dest.read_text(errors="replace"))
        if res.truncated:
            records = [r for r in records if r.ts is not None]
        return AlertRead(records=records, truncated=res.truncated, limit_bytes=max_bytes)

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
