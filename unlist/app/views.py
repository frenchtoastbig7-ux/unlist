"""Pages and form handlers. Every page reads through the same engine as the MCP tools."""

from __future__ import annotations

import json
import sqlite3
from datetime import date
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from unlist import __version__, paths
from unlist.app.jobs import JobContext, JobRunner
from unlist.catalog import load_catalog
from unlist.core.audit import AuditLog
from unlist.db import open_db
from unlist.monitor.run import JOBS, jobs_status
from unlist.requests import engine
from unlist.scanners.brokers import findings as F
from unlist.subjects import Consent, ConsentError, Identifier, Subject, SubjectRepo

router = APIRouter()
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
TEMPLATES.env.globals.update(version=__version__)


def conn() -> sqlite3.Connection:
    return open_db()


def render(request: Request, name: str, **ctx) -> HTMLResponse:
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    return TEMPLATES.TemplateResponse(request, name, ctx)


def back(url: str, msg: str = "") -> RedirectResponse:
    from urllib.parse import quote

    sep = "&" if "?" in url else "?"
    target = f"{url}{sep}msg={quote(msg)}" if msg else url
    return RedirectResponse(target, status_code=303)


def runner(request: Request) -> JobRunner:
    return request.app.state.runner


def _consent_state(s: Subject) -> str:
    if s.consent is None:
        return "none"
    try:
        s.consent.check(date.today())
        return f"until {s.consent.expires}"
    except ConsentError:
        return f"EXPIRED {s.consent.expires}"


# overview ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
def overview(request: Request):
    c = conn()
    repo = SubjectRepo(c)
    subjects = [(s, _consent_state(s)) for s in repo.list()]
    counts = {
        "breach_hits": c.execute("SELECT COUNT(*) FROM breach_hits").fetchone()[0],
        "candidates": c.execute(
            "SELECT COUNT(*) FROM findings WHERE status='candidate'"
        ).fetchone()[0],
        "confirmed": c.execute(
            "SELECT COUNT(*) FROM findings WHERE status IN ('confirmed','requested')"
        ).fetchone()[0],
        "removed": c.execute("SELECT COUNT(*) FROM findings WHERE status='removed'").fetchone()[0],
        "reappeared": c.execute(
            "SELECT COUNT(*) FROM findings WHERE status='reappeared'"
        ).fetchone()[0],
        "drafted": c.execute("SELECT COUNT(*) FROM requests WHERE state='drafted'").fetchone()[0],
        "open": len(engine.list_for(c, None, "open")),
        "overdue": c.execute("SELECT COUNT(*) FROM requests WHERE state='overdue'").fetchone()[0],
    }
    audit = AuditLog().entries(12)[::-1]
    jobs = JobRunner.recent(c, 5)
    return render(
        request,
        "overview.html",
        subjects=subjects,
        counts=counts,
        audit=audit,
        jobs=jobs,
        data_dir=str(paths.data_dir()),
        catalog_size=len(load_catalog()),
    )


# subjects ---------------------------------------------------------------------------


@router.get("/subjects/new", response_class=HTMLResponse)
def subject_new(request: Request):
    return render(request, "subject_new.html")


@router.post("/subjects")
def subject_create(
    request: Request,
    id: str = Form(...),
    label: str = Form(...),
    kind: str = Form("self"),
    residency_state: str = Form(""),
    residency_country: str = Form("US"),
    holder: str = Form(""),
    instrument: str = Form(""),
    expires: str = Form(""),
):
    c = conn()
    repo = SubjectRepo(c)
    try:
        consent = None
        if instrument and expires:
            consent = Consent(
                holder=holder or label,
                instrument=instrument,
                granted=date.today(),
                expires=date.fromisoformat(expires),
            )
        subject = Subject(
            id=id.strip(),
            label=label.strip(),
            kind=kind,
            residency_state=residency_state or None,
            residency_country=residency_country or "US",
            consent=consent,
        )
        repo.add(subject)
    except (ValueError, sqlite3.IntegrityError) as exc:
        return back("/subjects/new", f"Not created: {exc}")
    AuditLog().append("subject.add", subject=subject.id, kind=kind, via="app")
    return back(f"/subjects/{subject.id}", "Subject created. Add consent and identifiers.")


@router.get("/subjects/{sid}", response_class=HTMLResponse)
def subject_show(request: Request, sid: str):
    c = conn()
    try:
        s = SubjectRepo(c).get(sid)
    except KeyError:
        return PlainTextResponse("no such subject", status_code=404)
    hits = c.execute(
        "SELECT * FROM breach_hits WHERE subject_id=? ORDER BY COALESCE(breach_date,'') DESC",
        (sid,),
    ).fetchall()
    findings = F.list_for(c, sid)
    requests_ = engine.list_for(c, sid)
    return render(
        request,
        "subject.html",
        s=s,
        consent_state=_consent_state(s),
        hits=hits,
        findings=findings,
        requests=requests_,
        json=json,
    )


@router.post("/subjects/{sid}/consent")
def subject_consent(
    request: Request,
    sid: str,
    holder: str = Form(...),
    instrument: str = Form(...),
    expires: str = Form(...),
    scope_note: str = Form(""),
):
    c = conn()
    try:
        SubjectRepo(c).grant_consent(
            sid,
            Consent(
                holder=holder,
                instrument=instrument,
                granted=date.today(),
                expires=date.fromisoformat(expires),
                scope_note=scope_note,
            ),
        )
    except (KeyError, ValueError) as exc:
        return back(f"/subjects/{sid}", f"Not recorded: {exc}")
    AuditLog().append(
        "consent.grant",
        subject=sid,
        holder=holder,
        instrument=instrument,
        expires=expires,
        via="app",
    )
    return back(f"/subjects/{sid}", "Consent recorded.")


@router.post("/subjects/{sid}/identifiers")
def identifier_add(
    request: Request,
    sid: str,
    kind: str = Form(...),
    value: str = Form(...),
    current: str = Form("1"),
    city: str = Form(""),
    state: str = Form(""),
    zip: str = Form(""),
    from_year: str = Form(""),
    to_year: str = Form(""),
    relation: str = Form(""),
    note: str = Form(""),
):
    meta = {
        k: v
        for k, v in (
            ("city", city),
            ("state", state),
            ("zip", zip),
            ("from_year", from_year),
            ("to_year", to_year),
            ("relation", relation),
        )
        if v
    }
    c = conn()
    try:
        ident = SubjectRepo(c).add_identifier(
            sid,
            Identifier(
                subject_id=sid, kind=kind, value=value, current=current == "1", meta=meta, note=note
            ),
        )  # type: ignore[arg-type]
    except (KeyError, ValueError) as exc:
        return back(f"/subjects/{sid}", f"Not added: {exc}")
    AuditLog().append("identifier.add", subject=sid, kind=kind, identifier_id=ident.id, via="app")
    return back(f"/subjects/{sid}", f"Added {kind}.")


@router.post("/identifiers/{iid}/delete")
def identifier_delete(request: Request, iid: int, sid: str = Form(...)):
    SubjectRepo(conn()).remove_identifier(iid)
    AuditLog().append("identifier.remove", identifier_id=iid, via="app")
    return back(f"/subjects/{sid}", "Identifier removed.")


@router.post("/subjects/{sid}/scan/breaches")
def scan_breaches(request: Request, sid: str):
    from unlist.scanners.breaches import scan_breaches as run

    def job(ctx: JobContext) -> str:
        ctx.log(f"breach scan for {sid}")
        res = run(ctx.conn, sid)
        for k, v in res.skipped.items():
            ctx.log(f"skipped {k}: {v}")
        for e in res.errors:
            ctx.log(f"problem: {e}")
        return f"{res.new_hits} new hit(s), {res.seen_hits} already known"

    jid = runner(request).submit("scan breaches", job, {"subject": sid})
    return back(f"/jobs/{jid}")


@router.post("/subjects/{sid}/scan/brokers")
def scan_brokers(request: Request, sid: str, use_browser: str = Form("1"), brokers: str = Form("")):
    from unlist.scanners.brokers import scan_brokers as run
    from unlist.scanners.brokers.browser import BrowserSession, BrowserUnavailable

    ids = [b.strip() for b in brokers.split(",") if b.strip()]

    def job(ctx: JobContext) -> str:
        catalog = load_catalog()
        chosen = [catalog.get(i) for i in ids] if ids else catalog.searchable()
        ctx.log(f"people-search scan for {sid}: {len(chosen)} site(s)")
        browser = None
        if use_browser == "1":
            try:
                browser = BrowserSession()
                browser.start()
                ctx.log(
                    "browser ready; a Chromium window opens for sites that refuse plain fetches"
                )
            except BrowserUnavailable as exc:
                ctx.log(f"browser unavailable, HTTP only: {exc}")
        try:
            res = run(ctx.conn, sid, brokers=chosen, browser=browser)
        finally:
            if browser is not None:
                browser.close()
        for n in res.notes:
            ctx.log(n)
        ctx.log(json.dumps(res.counts))
        return f"{res.new_candidates} new candidate(s), {res.reappeared} reappeared, {res.challenged} challenged, {res.refused} refused"

    jid = runner(request).submit("scan people-search sites", job, {"subject": sid})
    return back(f"/jobs/{jid}")


@router.get("/subjects/{sid}/drop", response_class=HTMLResponse)
def drop_page(request: Request, sid: str):
    from unlist.requests.drop import drop_profile, drop_status_summary

    c = conn()
    try:
        text = drop_profile(c, sid)
    except ConsentError as exc:
        text = f"Refused: {exc}"
    return render(request, "drop.html", sid=sid, text=text, status=drop_status_summary(c, sid))


@router.post("/subjects/{sid}/drop")
def drop_record(request: Request, sid: str, drop_id: str = Form(...)):
    from unlist.requests.drop import record_drop

    try:
        record_drop(conn(), sid, drop_id)
    except (ConsentError, ValueError) as exc:
        return back(f"/subjects/{sid}/drop", f"Not recorded: {exc}")
    return back(f"/subjects/{sid}/drop", "DROP ID recorded.")


@router.get("/subjects/{sid}/report", response_class=HTMLResponse)
def exposure(request: Request, sid: str):
    from unlist.reports.exposure import write_exposure_report

    try:
        path, body = write_exposure_report(conn(), sid)
    except KeyError:
        return PlainTextResponse("no such subject", status_code=404)
    return render(request, "text.html", title=f"Exposure report: {sid}", text=body, path=str(path))


# findings ---------------------------------------------------------------------------


@router.get("/findings", response_class=HTMLResponse)
def findings_list(request: Request, subject: str = "", status: str = ""):
    c = conn()
    subjects = SubjectRepo(c).list()
    rows = []
    for s in subjects:
        if subject and s.id != subject:
            continue
        rows += F.list_for(c, s.id, status or None)
    out = [(r, json.loads(r["extract_json"] or "{}")) for r in rows]
    return render(
        request,
        "findings.html",
        rows=out,
        subjects=subjects,
        subject=subject,
        status=status,
        statuses=F.STATUSES,
    )


@router.get("/findings/{fid}", response_class=HTMLResponse)
def finding_show(request: Request, fid: int):
    c = conn()
    try:
        r = F.get(c, fid)
    except KeyError:
        return PlainTextResponse("no such finding", status_code=404)
    ex = json.loads(r["extract_json"] or "{}")
    cap = (
        c.execute("SELECT * FROM captures WHERE id=?", (r["capture_id"],)).fetchone()
        if r["capture_id"]
        else None
    )
    reqs = list(engine.list_for(c, r["subject_id"], None, r["broker_id"]))
    return render(request, "finding.html", r=r, ex=ex, cap=cap, requests=reqs, statuses=F.STATUSES)


@router.post("/findings/{fid}/status")
def finding_status(
    request: Request, fid: int, status: str = Form(...), note: str = Form(""), next: str = Form("")
):
    try:
        F.set_status(conn(), fid, status, note or None)
    except (KeyError, ValueError) as exc:
        return back(next or f"/findings/{fid}", str(exc))
    return back(next or f"/findings/{fid}", f"Finding {fid} marked {status}.")


@router.post("/findings/verify")
def findings_verify(request: Request, ids: str = Form(...), use_browser: str = Form("1")):
    from unlist.scanners.brokers import verify_finding
    from unlist.scanners.brokers.browser import BrowserSession, BrowserUnavailable

    fids = [int(x) for x in ids.replace(",", " ").split() if x.isdigit()]

    def job(ctx: JobContext) -> str:
        browser = None
        if use_browser == "1":
            try:
                browser = BrowserSession()
            except BrowserUnavailable:
                browser = None
        try:
            for fid in fids:
                try:
                    verdict, detail = verify_finding(ctx.conn, fid, browser=browser)
                except (KeyError, ConsentError) as exc:
                    verdict, detail = "error", str(exc)
                ctx.log(f"finding {fid}: {verdict} ({detail})")
        finally:
            if browser is not None:
                browser.close()
        return f"verified {len(fids)} finding(s)"

    jid = runner(request).submit("verify listings", job, {"ids": fids})
    return back(f"/jobs/{jid}")


@router.get("/evidence/{cid}/shot")
def evidence_shot(cid: int):
    cap = conn().execute("SELECT * FROM captures WHERE id=?", (cid,)).fetchone()
    if not cap or not cap["shot_path"]:
        return PlainTextResponse("no screenshot", status_code=404)
    return FileResponse(paths.data_dir() / cap["shot_path"], media_type="image/png")


@router.get("/evidence/{cid}/raw")
def evidence_raw(cid: int):
    cap = conn().execute("SELECT * FROM captures WHERE id=?", (cid,)).fetchone()
    if not cap:
        return PlainTextResponse("no capture", status_code=404)
    p = paths.data_dir() / cap["raw_path"]
    if not p.is_file():
        return PlainTextResponse("raw file missing", status_code=404)
    return PlainTextResponse(p.read_text(encoding="utf-8", errors="replace"))


# requests ---------------------------------------------------------------------------


@router.get("/requests", response_class=HTMLResponse)
def requests_list(request: Request, subject: str = "", state: str = ""):
    c = conn()
    rows = engine.list_for(c, subject or None, state or None)
    subjects = SubjectRepo(c).list()
    return render(
        request,
        "requests.html",
        rows=rows,
        subjects=subjects,
        subject=subject,
        state=state,
        states=("open", *engine.STATES),
    )


@router.get("/requests/{rid}", response_class=HTMLResponse)
def request_show(request: Request, rid: int):
    c = conn()
    try:
        r = engine.get(c, rid)
    except KeyError:
        return PlainTextResponse("no such request", status_code=404)
    events = engine.events_for(c, rid)
    replies = c.execute(
        "SELECT * FROM inbox_messages WHERE request_id=? ORDER BY id", (rid,)
    ).fetchall()
    listings = json.loads(r["listings_json"] or "[]")
    return render(
        request,
        "request.html",
        r=r,
        events=events,
        replies=replies,
        listings=listings,
        states=engine.STATES,
    )


@router.post("/requests/draft")
def requests_draft(
    request: Request,
    subject: str = Form(...),
    broker: str = Form(""),
    channel: str = Form(""),
    basis: str = Form(""),
):
    c = conn()
    try:
        if broker:
            fids = [
                f["id"]
                for f in F.list_for(c, subject, None, broker)
                if f["status"] in ("confirmed", "reappeared")
            ]
            rows = [
                engine.draft_request(
                    c, subject, broker, fids, channel=channel or None, basis=basis or None
                )
            ]
        else:
            rows = engine.draft_for_confirmed(
                c, subject, channel=channel or None, basis=basis or None
            )
    except (ConsentError, KeyError, ValueError) as exc:
        return back("/requests", f"Not drafted: {exc}")
    if not rows:
        return back("/requests", "Nothing to draft: no confirmed findings without an open request.")
    return back(
        "/requests?state=drafted", f"Drafted {len(rows)} request(s). Read and approve them."
    )


@router.post("/requests/draft-blind")
def requests_draft_blind(
    request: Request,
    subject: str = Form(...),
    category: str = Form(""),
    only_registry: str = Form("1"),
    limit: int = Form(25),
):
    try:
        rows = engine.draft_blind(
            conn(),
            subject,
            category=category or None,
            only_registry=only_registry == "1",
            limit=limit,
        )
    except (ConsentError, KeyError, ValueError) as exc:
        return back("/requests", f"Not drafted: {exc}")
    return back("/requests?state=drafted", f"Drafted {len(rows)} blind request(s).")


@router.post("/requests/{rid}/approve")
def request_approve(request: Request, rid: int, next: str = Form("")):
    rows = engine.approve(conn(), [rid])
    return back(next or f"/requests/{rid}", "Approved." if rows else "Not approved (not a draft).")


@router.post("/requests/approve-all")
def requests_approve_all(request: Request):
    c = conn()
    ids = [r["id"] for r in engine.list_for(c, None, "drafted")]
    rows = engine.approve(c, ids)
    return back("/requests?state=approved", f"Approved {len(rows)} request(s).")


@router.post("/requests/{rid}/state")
def request_state(request: Request, rid: int, state: str = Form(...), note: str = Form("")):
    c = conn()
    try:
        if state in ("sent", "submitted") and not engine.get(c, rid)["sent_at"]:
            engine.mark_sent(c, rid, state, note or None)
        else:
            engine.set_state(c, rid, state, note or None)
    except (KeyError, ValueError) as exc:
        return back(f"/requests/{rid}", str(exc))
    return back(f"/requests/{rid}", f"Now {state}.")


@router.post("/requests/send")
def requests_send(request: Request, ids: str = Form("")):
    from unlist.requests.mailer import Mailer, SmtpSettings

    chosen = [int(x) for x in ids.replace(",", " ").split() if x.isdigit()] or None

    def job(ctx: JobContext) -> str:
        settings = SmtpSettings.from_env()
        if settings is None:
            ctx.log(
                "no mailbox configured: set UNLIST_SMTP_HOST, UNLIST_SMTP_USER, UNLIST_SMTP_PASSWORD in .env"
            )
            return "nothing sent: no mailbox configured"
        results = engine.send_approved(ctx.conn, Mailer(settings), chosen)
        for rid, ok, detail in results:
            ctx.log(f"request {rid}: {'sent' if ok else 'NOT sent'}: {detail}")
        return f"{sum(1 for _, ok, _ in results if ok)} of {len(results)} sent"

    jid = runner(request).submit("send approved email requests", job, {"ids": chosen})
    return back(f"/jobs/{jid}")


@router.post("/requests/{rid}/form-open")
def request_form_open(request: Request, rid: int):
    from unlist.requests.form import launch_form_assist

    c = conn()
    try:
        r = engine.get(c, rid)
    except KeyError:
        return back("/requests", "no such request")
    if r["channel"] != "form" or r["state"] not in ("approved", "awaiting_verification"):
        return back(f"/requests/{rid}", "Only approved form requests can be opened.")
    pid = launch_form_assist(rid)
    return back(
        f"/requests/{rid}",
        f"Browser opened (helper pid {pid}). Finish the form there and close the window.",
    )


@router.post("/requests/{rid}/letter")
def request_letter(request: Request, rid: int):
    from unlist.requests.pdf import write_letter

    try:
        p = write_letter(conn(), rid)
    except KeyError:
        return back("/requests", "no such request")
    return back(f"/requests/{rid}", f"Letter written to {p}")


# inbox ------------------------------------------------------------------------------


@router.get("/inbox", response_class=HTMLResponse)
def inbox(request: Request):
    from unlist.requests.inbox import ImapSettings

    c = conn()
    rows = c.execute("SELECT * FROM inbox_messages ORDER BY id DESC LIMIT 100").fetchall()
    return render(request, "inbox.html", rows=rows, configured=ImapSettings.from_env() is not None)


@router.post("/inbox/poll")
def inbox_poll(request: Request):
    from unlist.requests.inbox import ImapInbox, ImapSettings, process_messages

    def job(ctx: JobContext) -> str:
        settings = ImapSettings.from_env()
        if settings is None:
            ctx.log("no mailbox configured (UNLIST_IMAP_HOST)")
            return "not configured"
        with ImapInbox(settings) as box:
            messages = box.fetch_unseen()
            results = process_messages(ctx.conn, messages)
            for m in messages:
                box.mark_seen(m.uid)
        for r in results:
            ctx.log(f"{r['from']}: {r['kind']}; {r['action']}")
        return f"{len(results)} message(s)"

    jid = runner(request).submit("poll inbox", job)
    return back(f"/jobs/{jid}")


# monitor, reports, catalog, jobs ---------------------------------------------------------


@router.get("/monitor", response_class=HTMLResponse)
def monitor(request: Request):
    c = conn()
    base = paths.reports_dir()
    reports = (
        sorted(base.glob("*/*.md"), key=lambda p: p.stat().st_mtime, reverse=True)[:40]
        if base.is_dir()
        else []
    )
    return render(
        request,
        "monitor.html",
        jobs=jobs_status(c),
        names=list(JOBS),
        reports=[str(p.relative_to(base)) for p in reports],
    )


@router.post("/monitor/run")
def monitor_run(
    request: Request, force: str = Form("0"), only: str = Form(""), use_browser: str = Form("1")
):
    from unlist.monitor import run_due

    chosen = {x.strip() for x in only.split(",") if x.strip()} or None

    def job(ctx: JobContext) -> str:
        s = run_due(ctx.conn, force=force == "1", use_browser=use_browser == "1", only=chosen)
        ctx.log(
            f"ran: {', '.join(s.ran) or 'nothing due'}; skipped: {', '.join(s.skipped) or 'none'}"
        )
        for ch in s.changes:
            ctx.log(f"change: {ch}")
        for p in s.problems:
            ctx.log(f"problem: {p}")
        ctx.log(f"report: {s.report_path}")
        return f"{len(s.changes)} change(s), {len(s.problems)} problem(s)"

    jid = runner(request).submit("monitor run", job, {"force": force, "only": only})
    return back(f"/jobs/{jid}")


@router.post("/monitor/interval")
def monitor_interval(request: Request, job: str = Form(...), interval: str = Form(...)):
    from unlist.monitor.run import set_interval

    try:
        set_interval(conn(), job, interval)
    except ValueError as exc:
        return back("/monitor", str(exc))
    return back("/monitor", f"{job} every {interval}.")


@router.get("/reports/{tool}/{name}", response_class=HTMLResponse)
def report_read(request: Request, tool: str, name: str):
    base = paths.reports_dir().resolve()
    p = (base / tool / name).resolve()
    if not str(p).startswith(str(base)) or not p.is_file():
        return PlainTextResponse("no such report", status_code=404)
    return render(
        request,
        "text.html",
        title=f"{tool}/{name}",
        text=p.read_text(encoding="utf-8"),
        path=str(p),
    )


@router.get("/catalog", response_class=HTMLResponse)
def catalog_list(request: Request, q: str = "", category: str = ""):
    cat = load_catalog()
    brokers = cat.search(q, limit=1000) if q else list(cat)
    if category:
        brokers = [b for b in brokers if b.category == category]
    return render(
        request,
        "catalog.html",
        brokers=brokers[:300],
        total=len(brokers),
        q=q,
        category=category,
        categories=sorted(cat.by_category()),
    )


@router.get("/catalog/{bid}", response_class=HTMLResponse)
def catalog_show(request: Request, bid: str):
    cat = load_catalog()
    if bid not in cat:
        return PlainTextResponse("no such broker", status_code=404)
    return render(request, "broker.html", b=cat.get(bid))


@router.get("/jobs", response_class=HTMLResponse)
def jobs_list(request: Request):
    return render(request, "jobs.html", jobs=JobRunner.recent(conn()))


@router.get("/jobs/{jid}", response_class=HTMLResponse)
def job_show(request: Request, jid: int):
    j = JobRunner.get(conn(), jid)
    if j is None:
        return PlainTextResponse("no such job", status_code=404)
    return render(request, "job.html", j=j)


@router.get("/audit", response_class=HTMLResponse)
def audit(request: Request):
    log = AuditLog()
    ok, detail = log.verify()
    return render(
        request, "audit.html", ok=ok, detail=detail, entries=log.entries(200)[::-1], json=json
    )
