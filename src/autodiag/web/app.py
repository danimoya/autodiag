"""One process: web UI (server-rendered), REST API (``/api/v1``) and the MCP endpoint (``/mcp``).

The UI and API call the same tool functions the MCP server exposes, so the three
interfaces cannot drift apart.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from jinja2 import Environment, FunctionLoader, select_autoescape
from starlette.middleware.base import BaseHTTPMiddleware

from autodiag import __version__
from autodiag.alertlog.stats import alert_stats
from autodiag.alertlog.text import parse_alert_text
from autodiag.alertlog.window import grep_records, window
from autodiag.case.store import CaseStoreError
from autodiag.diff.callstack import compare_stacks, stack_from_incident
from autodiag.diff.sqlprofile import compare_profiles
from autodiag.mcp.server import AutoDiagContext, build_server
from autodiag.report.build import build_context
from autodiag.report.render import render_report
from autodiag.trace.incident import IncidentTrace
from autodiag.trace.registry import parse_trace
from autodiag.trace.sqltrace import parse_sqltrace


def _tpl_loader(name: str) -> str | None:
    p = Path(__file__).parent / "templates" / name
    return p.read_text() if p.is_file() else None


def _env() -> Environment:
    env = Environment(
        loader=FunctionLoader(_tpl_loader),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["ts"] = lambda v: (
        v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, datetime) else (v or "-")
    )
    env.filters["us"] = lambda v: f"{(v or 0) / 1e6:.3f}s"
    env.filters["pct"] = lambda v: f"{round(float(v) * 100)}%"
    env.filters["json"] = lambda v: json.dumps(v, indent=2, default=str)
    return env


class BearerMiddleware(BaseHTTPMiddleware):
    """Protects /api and /mcp with a static bearer token when one is configured."""

    def __init__(self, app, token: str | None) -> None:
        super().__init__(app)
        self.token = token

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if self.token and (path.startswith("/api/") or path == "/mcp" or path.startswith("/mcp/")):
            auth = request.headers.get("authorization", "")
            if auth != f"Bearer {self.token}":
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


def create_app(ctx: AutoDiagContext) -> FastAPI:
    mcp = build_server(ctx)
    mcp_app = mcp.http_app(path="/mcp", stateless_http=True, json_response=True)
    app = FastAPI(
        title="AutoDiag",
        version=__version__,
        lifespan=mcp_app.lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(BearerMiddleware, token=ctx.settings.mcp_token)
    env = _env()
    st = ctx.store

    async def tool_fn(name: str):
        try:
            tool = await mcp.get_tool(name)
        except Exception:  # noqa: BLE001 - unknown tool names are a 404
            tool = None
        if tool is None:
            raise HTTPException(404, f"unknown tool {name!r}")
        return tool.fn

    def render(name: str, **kw: Any) -> HTMLResponse:
        return HTMLResponse(env.get_template(name).render(version=__version__, **kw))

    # ------------------------------------------------------------------ basics
    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "targets": ctx.inventory.names()}

    @app.get("/", include_in_schema=False)
    def index() -> RedirectResponse:
        return RedirectResponse("/cases", status_code=302)

    # ------------------------------------------------------------------ REST: generic tool endpoint
    @app.get("/api/v1/tools")
    async def api_tools() -> dict[str, Any]:
        tools = await mcp.list_tools()
        return {"tools": [{"name": t.name, "description": t.description} for t in tools]}

    @app.post("/api/v1/tools/{name}")
    async def api_tool(name: str, request: Request) -> JSONResponse:
        fn = await tool_fn(name)
        body = await request.json() if await request.body() else {}
        try:
            result = fn(**(body or {}))
        except TypeError as exc:
            raise HTTPException(422, str(exc)) from None
        return JSONResponse(json.loads(json.dumps(result, default=str)))

    # ------------------------------------------------------------------ targets
    @app.get("/targets", response_class=HTMLResponse)
    def targets_page() -> HTMLResponse:
        return render("targets.html", targets=ctx.inventory.targets)

    @app.get("/targets/{name}", response_class=HTMLResponse)
    def target_page(name: str) -> HTMLResponse:
        t = ctx.target(name)
        return render(
            "target.html",
            t=t,
            baselines=st.list_baselines(t.name),
            cases=st.list_cases(target=t.name),
        )

    @app.get("/targets/{name}/problems", response_class=HTMLResponse)
    def problems_page(name: str, days: int = 7) -> HTMLResponse:
        t = ctx.target(name)
        rows = ctx.source(t).list_problems(days=days)
        st.upsert_problems(t.name, rows)
        return render("problems.html", t=t, problems=rows, days=days)

    @app.get("/targets/{name}/problems/{problem_id}", response_class=HTMLResponse)
    def incidents_page(name: str, problem_id: int) -> HTMLResponse:
        t = ctx.target(name)
        rows = ctx.source(t).list_incidents(problem_id=problem_id)
        return render(
            "incidents.html",
            t=t,
            problem_id=problem_id,
            incidents=rows,
            cases=st.list_cases(target=t.name, status="open"),
        )

    @app.post("/targets/{name}/problems/{problem_id}/triage")
    async def triage_action(
        name: str, problem_id: int, problem_key: str = Form(...)
    ) -> RedirectResponse:
        fn = await tool_fn("standard_triage")
        result = fn(target=name, problem_key=problem_key)
        if "error" in result:
            raise HTTPException(500, result["error"])
        return RedirectResponse(f"/cases/{result['case_id']}", status_code=303)

    @app.post("/targets/{name}/diagnose")
    def diagnose_action(
        name: str,
        mode: str = Form(...),
        problem_key: str = Form(""),
        hours: float = Form(24.0),
        days: int = Form(7),
        live: str = Form("auto"),
    ) -> RedirectResponse:
        from autodiag.diagnose.engine import diagnose
        from autodiag.diagnose.render import diagnosis_markdown

        kw: dict[str, Any] = {}
        if mode == "problem":
            kw["problem_key"] = problem_key
        elif mode == "alert":
            kw["hours"] = hours
        elif mode == "instance":
            kw.update(days=days, hours=hours, live=None if live == "auto" else live == "yes")
        else:
            raise HTTPException(422, f"unknown mode {mode!r}")
        try:
            d = diagnose(ctx, mode=mode, target=name, record=True, assess=True, **kw)
        except Exception as exc:  # noqa: BLE001 - surface collector/transport failures
            raise HTTPException(500, f"{type(exc).__name__}: {exc}") from None
        rep = st.add_report(d.case_id, kind="diagnosis", markdown=diagnosis_markdown(d))
        return RedirectResponse(f"/reports/{rep.id}", status_code=303)

    @app.get("/targets/{name}/alertlog", response_class=HTMLResponse)
    def alertlog_page(
        name: str, hours: float = 24, grep: str = "", context: int = 3, top: int = 20
    ) -> HTMLResponse:
        t = ctx.target(name)
        src = ctx.source(t)
        node, home = src.primary_ref()
        dest = ctx.cache_dir(t) / f"alert_{node.instance or 'db'}.log"
        src.fetch_file(node, src.alert_log_path(node, home), dest, max_bytes=64 * 1024 * 1024)
        recs = parse_alert_text(dest.read_text(errors="replace"))
        from datetime import UTC, timedelta

        sel = window(recs, datetime.now(UTC) - timedelta(hours=hours), None)
        stats = alert_stats(sel, top=top)
        hits = grep_records(sel, grep, context=context, max_hits=200) if grep else []
        return render(
            "alertlog.html", t=t, hours=hours, grep=grep, context=context, stats=stats, hits=hits
        )

    # ------------------------------------------------------------------ cases
    @app.get("/cases", response_class=HTMLResponse)
    def cases_page(target: str | None = None) -> HTMLResponse:
        return render(
            "cases.html", cases=st.list_cases(target=target), targets=ctx.inventory.targets
        )

    @app.post("/cases")
    def create_case(
        target: str = Form(...), title: str = Form(...), problem_keys: str = Form("")
    ) -> RedirectResponse:
        ctx.target(target)
        keys = [k.strip() for k in problem_keys.split(",") if k.strip()]
        c = st.open_case(target, title, problem_keys=keys)
        return RedirectResponse(f"/cases/{c.id}", status_code=303)

    @app.get("/cases/{case_id}", response_class=HTMLResponse)
    def case_page(case_id: str) -> HTMLResponse:
        try:
            c = st.get_case(case_id)
        except CaseStoreError:
            raise HTTPException(404, "unknown case") from None
        return render(
            "case.html",
            c=c,
            artifacts=st.list_artifacts(c.id),
            evidence=st.list_evidence(c.id),
            findings=st.list_findings(c.id),
            reports=st.list_reports(c.id),
            baselines=st.list_baselines(c.target),
        )

    @app.post("/cases/{case_id}/upload")
    async def upload_artifact(
        case_id: str, file: UploadFile = File(...), kind: str = Form("trace"), label: str = Form("")
    ) -> RedirectResponse:
        c = st.get_case(case_id)
        t = ctx.target(c.target)
        dest = (
            ctx.cache_dir(t)
            / "uploads"
            / re.sub(r"[^A-Za-z0-9._-]", "_", file.filename or "upload.txt")
        )
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(await file.read())
        st.add_artifact(
            c.id,
            kind=kind,
            path=dest,
            origin={"source": "upload", "filename": file.filename},
            label=label,
        )
        return RedirectResponse(f"/cases/{c.id}", status_code=303)

    @app.post("/cases/{case_id}/evidence")
    def add_evidence(
        case_id: str, summary: str = Form(...), tool: str = Form("manual")
    ) -> RedirectResponse:
        st.record_evidence(tool, {}, summary, case_id=case_id)
        return RedirectResponse(f"/cases/{case_id}", status_code=303)

    @app.post("/cases/{case_id}/findings")
    def add_finding(
        case_id: str,
        kind: str = Form(...),
        title: str = Form(...),
        detail: str = Form(""),
        confidence: float = Form(0.5),
        evidence_ids: str = Form(...),
    ) -> RedirectResponse:
        ids = [e.strip() for e in evidence_ids.split(",") if e.strip()]
        try:
            st.add_finding(
                case_id,
                kind=kind,
                title=title,
                detail=detail,
                confidence=confidence,
                evidence_ids=ids,
                author="human",
            )
        except CaseStoreError as exc:
            raise HTTPException(400, str(exc)) from None
        return RedirectResponse(f"/cases/{case_id}", status_code=303)

    @app.post("/cases/{case_id}/findings/{finding_id}")
    def update_finding(
        case_id: str, finding_id: str, status: str = Form(...), confidence: float = Form(None)
    ) -> RedirectResponse:
        fields: dict[str, Any] = {"status": status}
        if confidence is not None:
            fields["confidence"] = confidence
        st.update_finding(finding_id, **fields)
        return RedirectResponse(f"/cases/{case_id}", status_code=303)

    @app.post("/cases/{case_id}/baselines")
    def add_baseline(
        case_id: str, artifact_id: str = Form(...), kind: str = Form(...), label: str = Form("")
    ) -> RedirectResponse:
        c = st.get_case(case_id)
        st.set_baseline(c.target, kind=kind, artifact_id=artifact_id, label=label)
        return RedirectResponse(f"/cases/{case_id}", status_code=303)

    @app.post("/cases/{case_id}/reports")
    def make_report(
        case_id: str, kind: str = Form("dba"), capture_env: bool = Form(False)
    ) -> RedirectResponse:
        c = st.get_case(case_id)
        t = ctx.target(c.target)
        rctx = build_context(
            st,
            case_id,
            target=t,
            transport_factory=ctx.transport_factory(t),
            runner=ctx.runner(t) if capture_env else None,
            capture_env=capture_env,
        )
        r = st.add_report(case_id, kind=kind, markdown=render_report(kind, rctx))
        return RedirectResponse(f"/reports/{r.id}", status_code=303)

    @app.post("/cases/{case_id}/close")
    def close_case(case_id: str) -> RedirectResponse:
        st.close_case(case_id)
        return RedirectResponse(f"/cases/{case_id}", status_code=303)

    # ------------------------------------------------------------------ reports
    @app.get("/reports/{report_id}.md")
    def report_markdown(report_id: str) -> Response:
        r = st.get_report(report_id)
        return Response(
            r.markdown,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{r.id}_{r.kind}.md"'},
        )

    @app.get("/reports/{report_id}", response_class=HTMLResponse)
    def report_page(report_id: str) -> HTMLResponse:
        r = st.get_report(report_id)
        return render("report.html", r=r, body=_md_to_html(r.markdown))

    # ------------------------------------------------------------------ artifacts / traces
    @app.get("/artifacts/{artifact_id}", response_class=HTMLResponse)
    def artifact_page(artifact_id: str) -> HTMLResponse:
        a = st.get_artifact(artifact_id)
        text = Path(a.path).read_text(errors="replace")
        doc = parse_trace(text)
        summary = doc.summary_lines() if hasattr(doc, "summary_lines") else []
        extra = doc.model_dump(
            mode="json",
            exclude={
                "header",
                "sections",
                "timestamps",
                "ora_lines",
                "call_stack",
                "cursors",
                "waits",
            },
        )
        return render(
            "artifact.html",
            a=a,
            doc=doc,
            summary=summary,
            extra=extra,
            n=200,
            is_incident=isinstance(doc, IncidentTrace),
        )

    @app.get("/artifacts/{artifact_id}/lines", response_class=HTMLResponse)
    def artifact_lines(
        artifact_id: str, offset: int = 0, n: int = 200, grep: str = ""
    ) -> HTMLResponse:
        a = st.get_artifact(artifact_id)
        lines = Path(a.path).read_text(errors="replace").splitlines()
        if grep:
            lines = [f"{i + 1}: {ln}" for i, ln in enumerate(lines) if grep in ln]
        n = max(1, min(n, 2000))
        page = lines[offset : offset + n]
        return render(
            "lines.html", a=a, lines=page, offset=offset, n=n, total=len(lines), grep=grep
        )

    @app.get("/artifacts/{artifact_id}/raw")
    def artifact_raw(artifact_id: str) -> PlainTextResponse:
        a = st.get_artifact(artifact_id)
        return PlainTextResponse(Path(a.path).read_text(errors="replace"))

    # ------------------------------------------------------------------ diffs
    @app.get("/diff/stacks", response_class=HTMLResponse)
    def diff_stacks(left: str, right: str) -> HTMLResponse:
        a, b = st.get_artifact(left), st.get_artifact(right)
        da, db = (
            parse_trace(Path(a.path).read_text(errors="replace")),
            parse_trace(Path(b.path).read_text(errors="replace")),
        )
        if not isinstance(da, IncidentTrace) or not isinstance(db, IncidentTrace):
            raise HTTPException(400, "both artifacts must be incident traces")
        d = compare_stacks(stack_from_incident(da).frames, stack_from_incident(db).frames)
        return render("diff_stacks.html", a=a, b=b, da=da, db=db, d=d)

    @app.get("/diff/sqlprofile", response_class=HTMLResponse)
    def diff_sqlprofile(left: str, right: str, top: int = 15) -> HTMLResponse:
        a, b = st.get_artifact(left), st.get_artifact(right)
        d = compare_profiles(
            parse_sqltrace(Path(a.path).read_text(errors="replace")),
            parse_sqltrace(Path(b.path).read_text(errors="replace")),
            top=top,
        )
        return render("diff_sqlprofile.html", a=a, b=b, d=d)

    # the MCP endpoint answers everything not matched above (/mcp)
    app.mount("/", mcp_app)
    return app


_H = re.compile(r"^(#{1,6})\s+(.*)$")


def _md_to_html(md: str) -> str:
    """Tiny Markdown subset (headings, bullets, code spans, paragraphs) for report display."""
    out: list[str] = []
    in_list = False
    for raw in md.splitlines():
        line = html.escape(raw)
        line = re.sub(r"`([^`]+)`", r"<code>\1</code>", line)
        line = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", line)
        m = _H.match(line)
        if m:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h{len(m.group(1))}>{m.group(2)}</h{len(m.group(1))}>")
        elif line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{line[2:]}</li>")
        elif line.strip() == "":
            if in_list:
                out.append("</ul>")
                in_list = False
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<p>{line}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)
