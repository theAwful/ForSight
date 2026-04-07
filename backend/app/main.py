"""ForSight API: projects, ROE upload, checklist, scan jobs."""

import json
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import BackgroundTasks, Depends, File, HTTPException, UploadFile, Body
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.checklist import (
    CHECKLIST,
    PRE_ENGAGEMENT_GATE_ITEM_IDS,
    get_checklist_by_phase,
    get_item_id_by_runner_key,
    get_runner_keys_for_phase,
    Phase,
)
from app.database import get_db, init_database
from app.jobs import get_project_results_dir, get_project_targets, run_runner_sync, init_job_output_file
from app.nmap_parse import nmap_output_exists
from app.nessus_parse import parse_nessus_xml
from app.models import ChecklistStatus, Project, ProjectExcludedHost, ScanJob, RoadmapItem, Feedback
from app.roe import parse_roe_content
from pydantic import BaseModel
from app.schemas import (
    ChecklistItemOut,
    ChecklistPhaseOut,
    ProjectCreate,
    ProjectOut,
    ROEUploadResult,
    ScanJobOut,
    RoadmapItemOut,
    FeedbackOut,
    FeedbackCreate,
)

init_database()

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.auth import get_current_user, verify_credentials
from app.config import settings
from app import tenable_client
from app.tenable_client import TenableAPIError
from app import nessus_web_launch


def _sanitize_nessus_web_error(msg: str) -> str:
    """Avoid sending raw Chrome/Selenium crash stacktraces to the client."""
    if not msg or len(msg) < 500:
        return msg or "Web automation failed."
    if "Stacktrace" in msg or "#0 0x" in msg or "<unknown>" in msg:
        return (
            "Create via web failed (browser automation error). "
            "Try \"Create scan (API)\" or create the scan in Nessus and use Launch/Import here."
        )
    return msg[:500] + "…"

app = FastAPI(
    title="ForSight",
    description="Automated external penetration testing – wrapper for pentesting tools",
    version="0.1.0",
)

# Serve built MkDocs site at /docs (Docker builds docs into /app/site)
_docs_dir = Path("/app/site")
if _docs_dir.is_dir():
    app.mount("/docs", StaticFiles(directory=str(_docs_dir), html=True), name="docs")

# CORS: allow frontend origin(s). With credentials, browsers require an explicit origin (not "*").
# The CORS error for data.nessus-telemetry.tenable.com is from the Nessus UI in another tab, not ForSight.
_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
]
if settings.debug:
    _origins.extend(["http://localhost:5000", "http://127.0.0.1:5000"])
if getattr(settings, "cors_origins", None):
    _origins.extend(o.strip() for o in settings.cors_origins.split(",") if o.strip())
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)


class AuthRequiredMiddleware:
    """Require session for all /api/* except /api/auth/login and /api/health."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path.startswith("/api/") and path not in ("/api/auth/login", "/api/health"):
            request = Request(scope, receive, send)
            username = request.session.get("username")
            if not username:
                response = JSONResponse({"detail": "Not authenticated"}, status_code=401)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


# Order matters: last added = outermost = runs first. Session must run before auth check.
app.add_middleware(AuthRequiredMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="forsight_session",
    max_age=86400 * 7,  # 7 days
    same_site="lax",
    https_only=False,
)

executor = ThreadPoolExecutor(max_workers=16)


# ---- Auth (no Depends(get_current_user) - middleware allows these paths) ----
class LoginBody(BaseModel):
    username: str = ""
    password: str = ""


@app.post("/api/auth/login")
async def login(request: Request, body: LoginBody):
    """Authenticate with username/password. Sets session cookie. Default: forsight/forsight."""
    if not verify_credentials(body.username.strip(), body.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    request.session["username"] = body.username.strip().lower()
    return {"username": request.session["username"]}


@app.post("/api/auth/logout")
async def logout(request: Request):
    """Clear session (logout)."""
    request.session.clear()
    return {"ok": True}


@app.get("/api/auth/me")
def auth_me(request: Request):
    """Return current user if authenticated. Used by frontend to check auth state."""
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"username": username}


def ensure_checklist_status(project_id: int, db: Session) -> None:
    existing = {s.item_id for s in db.query(ChecklistStatus).filter(ChecklistStatus.project_id == project_id)}
    for item in CHECKLIST:
        if item.id not in existing:
            db.add(ChecklistStatus(project_id=project_id, item_id=item.id, status="not_started"))
    db.commit()


def pre_engagement_gate_passed(project_id: int, db: Session) -> bool:
    """Both Scope and Client-notified checklist items must be marked completed."""
    ensure_checklist_status(project_id, db)
    rows = {
        r.item_id: (r.status or "")
        for r in db.query(ChecklistStatus).filter(
            ChecklistStatus.project_id == project_id,
            ChecklistStatus.item_id.in_(PRE_ENGAGEMENT_GATE_ITEM_IDS),
        )
    }
    return all(rows.get(iid) == "completed" for iid in PRE_ENGAGEMENT_GATE_ITEM_IDS)


def require_pre_engagement_for_scans(project_id: int, db: Session) -> None:
    if not pre_engagement_gate_passed(project_id, db):
        raise HTTPException(
            status_code=403,
            detail="Confirm Scope and Client notified (Pre-engagement) before running scans.",
        )


@app.post("/api/projects", response_model=ProjectOut)
def create_project(body: ProjectCreate, db: Session = Depends(get_db)):
    p = Project(name=body.name)
    db.add(p)
    db.commit()
    db.refresh(p)
    ensure_checklist_status(p.id, db)
    out = ProjectOut(
        id=p.id,
        name=p.name,
        created_at=p.created_at,
        roe_filename=p.roe_filename,
        targets_summary=None,
    )
    if p.targets_raw:
        data = json.loads(p.targets_raw)
        out.targets_summary = {"ips": len(data.get("ips", [])), "domains": len(data.get("domains", []))}
    return out


@app.get("/api/projects", response_model=List[ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    projects = db.query(Project).order_by(Project.created_at.desc()).all()
    return [
        ProjectOut(
            id=p.id,
            name=p.name,
            created_at=p.created_at,
            roe_filename=p.roe_filename,
            targets_summary=({"ips": len(d.get("ips", [])), "domains": len(d.get("domains", []))} if p.targets_raw and (d := json.loads(p.targets_raw)) else None),
        )
        for p in projects
    ]


@app.get("/api/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: int, db: Session = Depends(get_db)):
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    d = json.loads(p.targets_raw) if p.targets_raw else {}
    return ProjectOut(
        id=p.id,
        name=p.name,
        created_at=p.created_at,
        roe_filename=p.roe_filename,
        targets_summary={"ips": len(d.get("ips", [])), "domains": len(d.get("domains", []))} if d else None,
    )


@app.get("/api/projects/{project_id}/nmap-ready")
def get_project_nmap_ready(project_id: int, db: Session = Depends(get_db)):
    """Return whether Nmap has been run for this project (so Enumeration/Web host Run buttons can be enabled)."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    results_dir = get_project_results_dir(project_id)
    return {"nmap_done": nmap_output_exists(results_dir)}


@app.delete("/api/projects/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db)):
    """Delete a project and its jobs, checklist status, results dir, and uploads."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    db.query(ScanJob).filter(ScanJob.project_id == project_id).delete()
    db.query(ChecklistStatus).filter(ChecklistStatus.project_id == project_id).delete()
    db.delete(p)
    db.commit()
    results_dir = Path("data/results") / str(project_id)
    if results_dir.exists():
        shutil.rmtree(results_dir, ignore_errors=True)
    uploads_dir = Path("data/uploads")
    if uploads_dir.exists():
        for f in uploads_dir.glob(f"{project_id}_*"):
            try:
                f.unlink()
            except OSError:
                pass
    return {"deleted": project_id}


@app.post("/api/projects/{project_id}/roe", response_model=ROEUploadResult)
async def upload_roe(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    content = (await file.read()).decode("utf-8", errors="replace")
    ips, domains = parse_roe_content(content, file.filename or "")
    targets = json.dumps({"ips": ips, "domains": domains})
    p.targets_raw = targets
    p.roe_filename = file.filename
    upload_path = Path("data/uploads") / f"{project_id}_{file.filename or 'roe.txt'}"
    upload_path.parent.mkdir(parents=True, exist_ok=True)
    upload_path.write_text(content)
    p.roe_path = str(upload_path)
    db.commit()
    return ROEUploadResult(
        project_id=project_id,
        filename=file.filename or "roe",
        ips_count=len(ips),
        domains_count=len(domains),
    )


class ROEPasteBody(BaseModel):
    content: str


@app.post("/api/projects/{project_id}/roe/paste", response_model=ROEUploadResult)
async def paste_roe(
    project_id: int,
    body: ROEPasteBody,
    db: Session = Depends(get_db),
):
    """Paste IPs/domains (one per line). Input is sanitized before parsing."""
    from app.roe import sanitize_roe_input, parse_roe_content
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    content = sanitize_roe_input(body.content)
    ips, domains = parse_roe_content(content, "")
    targets = json.dumps({"ips": ips, "domains": domains})
    p.targets_raw = targets
    p.roe_filename = "pasted.txt"
    upload_path = Path("data/uploads") / f"{project_id}_pasted.txt"
    upload_path.parent.mkdir(parents=True, exist_ok=True)
    upload_path.write_text(content)
    p.roe_path = str(upload_path)
    db.commit()
    return ROEUploadResult(
        project_id=project_id,
        filename="pasted.txt",
        ips_count=len(ips),
        domains_count=len(domains),
    )


@app.get("/api/projects/{project_id}/targets")
def get_project_targets_api(project_id: int, db: Session = Depends(get_db)):
    """Return current target list (IPs and domains) for viewing/editing."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    ips, domains = get_project_targets(p)
    return {"ips": ips, "domains": domains}


class TargetsUpdateBody(BaseModel):
    content: str


@app.put("/api/projects/{project_id}/targets")
def update_project_targets(
    project_id: int,
    body: TargetsUpdateBody,
    db: Session = Depends(get_db),
):
    """Update target list from pasted content (one per line). Updates the same store tools use."""
    from app.roe import sanitize_roe_input, parse_roe_content
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    content = sanitize_roe_input(body.content)
    ips, domains = parse_roe_content(content, "")
    p.targets_raw = json.dumps({"ips": ips, "domains": domains})
    p.roe_filename = "edited.txt"
    db.commit()
    return {"ips_count": len(ips), "domains_count": len(domains)}


@app.get("/api/checklist", response_model=dict)
def get_checklist():
    return get_checklist_by_phase()


@app.get("/api/projects/{project_id}/checklist", response_model=List[ChecklistPhaseOut])
def get_project_checklist(project_id: int, db: Session = Depends(get_db)):
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    ensure_checklist_status(project_id, db)
    status_map = {s.item_id: s for s in db.query(ChecklistStatus).filter(ChecklistStatus.project_id == project_id)}
    by_phase = get_checklist_by_phase()
    result = []
    for phase, items in by_phase.items():
        result.append(
            ChecklistPhaseOut(
                phase=phase,
                items=[
                    ChecklistItemOut(
                        id=it["id"],
                        phase=phase,
                        description=it["description"],
                        runner_key=it.get("runner_key"),
                        tools=it.get("tools", []),
                        status=(status_map[it["id"]].status or "not_started") if it["id"] in status_map else "not_started",
                        notes=(status_map[it["id"]].notes or None) if it["id"] in status_map else None,
                    )
                    for it in items
                ],
            )
        )
    return result


@app.patch("/api/projects/{project_id}/checklist/{item_id}")
def update_checklist_item(
    project_id: int,
    item_id: str,
    status: Optional[str] = None,
    notes: Optional[str] = None,
    db: Session = Depends(get_db),
):
    row = db.query(ChecklistStatus).filter(
        ChecklistStatus.project_id == project_id,
        ChecklistStatus.item_id == item_id,
    ).first()
    if not row:
        raise HTTPException(404, "Checklist item not found")
    if status is not None:
        row.status = status
    if notes is not None:
        row.notes = notes
    db.commit()
    return {"item_id": item_id, "status": row.status, "notes": row.notes}


class RunScanOptions(BaseModel):
    use_nmap: bool = False


@app.post("/api/projects/{project_id}/run/{runner_key}", response_model=ScanJobOut)
def run_scan(
    project_id: int,
    runner_key: str,
    body: Optional[RunScanOptions] = Body(None),
    db: Session = Depends(get_db),
):
    from app.runners import RUNNERS
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    require_pre_engagement_for_scans(project_id, db)
    if runner_key not in RUNNERS:
        raise HTTPException(400, f"Unknown runner: {runner_key}")
    job = ScanJob(
        project_id=project_id,
        runner_key=runner_key,
        status="pending",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    item_id = get_item_id_by_runner_key(runner_key)
    if item_id:
        row = db.query(ChecklistStatus).filter(
            ChecklistStatus.project_id == project_id,
            ChecklistStatus.item_id == item_id,
        ).first()
        if row:
            row.status = "in_progress"
            db.commit()

    run_options = {}
    if body and getattr(body, "use_nmap", None) is not None:
        run_options["use_nmap"] = bool(body.use_nmap)

    # Create output file and set output_path immediately so Output tab can show live output
    # before the executor runs (avoids 404 and "Failed to load output")
    results_dir = get_project_results_dir(project_id)
    results_dir.mkdir(parents=True, exist_ok=True)
    ips, domains = get_project_targets(p)
    stream_path = results_dir / f"job_{job.id}.txt"
    init_job_output_file(stream_path, runner_key, ips, domains)
    job.output_path = str(stream_path)
    db.commit()

    def run():
        from app.database import SessionLocal
        local_db = SessionLocal()
        try:
            proj = local_db.query(Project).filter(Project.id == project_id).first()
            j = local_db.query(ScanJob).filter(ScanJob.id == job.id).first()
            if not proj or not j:
                return
            run_runner_sync(runner_key, proj, job=j, db=local_db, run_options=run_options)
        except Exception as e:
            try:
                fix_db = SessionLocal()
                try:
                    jb = fix_db.query(ScanJob).filter(ScanJob.project_id == project_id, ScanJob.id == job.id).first()
                    if jb and jb.status in ("pending", "running"):
                        jb.status = "failed"
                        jb.error_message = str(e)[:2000]
                        from datetime import datetime
                        jb.finished_at = datetime.utcnow()
                        fix_db.commit()
                finally:
                    fix_db.close()
            except Exception:
                pass
        finally:
            local_db.close()

    executor.submit(run)
    return ScanJobOut(
        id=job.id,
        project_id=job.project_id,
        runner_key=job.runner_key,
        status=job.status,
        started_at=job.started_at,
        finished_at=job.finished_at,
        output_path=job.output_path,
        error_message=job.error_message,
    )


@app.post("/api/projects/{project_id}/run-phase/{phase}")
def run_phase(
    project_id: int,
    phase: str,
    body: Optional[RunScanOptions] = Body(None),
    db: Session = Depends(get_db),
):
    """Start all runners in a phase in parallel (e.g. Recon: subfinder, dnsrecon, amass, ...)."""
    from app.runners import RUNNERS
    try:
        phase_enum = Phase(phase)
    except ValueError:
        raise HTTPException(400, f"Unknown phase: {phase}")
    runner_keys = get_runner_keys_for_phase(phase_enum)
    if not runner_keys:
        return {"message": "No runnable items in this phase", "jobs": []}
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    require_pre_engagement_for_scans(project_id, db)
    run_options = {}
    if body and getattr(body, "use_nmap", None) is not None:
        run_options["use_nmap"] = bool(body.use_nmap)
    jobs_created = []
    for rk in runner_keys:
        if rk not in RUNNERS:
            continue
        job = ScanJob(project_id=project_id, runner_key=rk, status="pending")
        db.add(job)
        db.commit()
        db.refresh(job)
        item_id = get_item_id_by_runner_key(rk)
        if item_id:
            row = db.query(ChecklistStatus).filter(
                ChecklistStatus.project_id == project_id,
                ChecklistStatus.item_id == item_id,
            ).first()
            if row:
                row.status = "in_progress"
        db.commit()
        # Create output file immediately so Output tab shows live output before executor runs
        results_dir = get_project_results_dir(project_id)
        results_dir.mkdir(parents=True, exist_ok=True)
        ips, domains = get_project_targets(p)
        stream_path = results_dir / f"job_{job.id}.txt"
        init_job_output_file(stream_path, rk, ips, domains)
        job.output_path = str(stream_path)
        db.commit()
        jobs_created.append(ScanJobOut.model_validate(job))

        def run_one(runner_key=rk, j=job):
            from app.database import SessionLocal
            local_db = SessionLocal()
            try:
                proj = local_db.query(Project).filter(Project.id == project_id).first()
                jb = local_db.query(ScanJob).filter(ScanJob.id == j.id).first()
                if not proj or not jb:
                    return
                run_runner_sync(runner_key, proj, job=jb, db=local_db, run_options=run_options)
            except Exception as e:
                try:
                    fix_db = SessionLocal()
                    try:
                        jb2 = fix_db.query(ScanJob).filter(ScanJob.project_id == project_id, ScanJob.id == j.id).first()
                        if jb2 and jb2.status in ("pending", "running"):
                            jb2.status = "failed"
                            jb2.error_message = str(e)[:2000]
                            from datetime import datetime
                            jb2.finished_at = datetime.utcnow()
                            fix_db.commit()
                    finally:
                        fix_db.close()
                except Exception:
                    pass
            finally:
                local_db.close()

        executor.submit(run_one)
    return {"message": f"Started {len(jobs_created)} jobs", "jobs": jobs_created}


@app.get("/api/projects/{project_id}/jobs", response_model=List[ScanJobOut])
def list_scan_jobs(project_id: int, db: Session = Depends(get_db)):
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    jobs = db.query(ScanJob).filter(ScanJob.project_id == project_id).order_by(ScanJob.id.desc()).all()
    return [ScanJobOut.model_validate(j) for j in jobs]


@app.get("/api/projects/{project_id}/jobs/{job_id}", response_model=ScanJobOut)
def get_scan_job(project_id: int, job_id: int, db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.project_id == project_id, ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    return ScanJobOut.model_validate(job)


@app.post("/api/projects/{project_id}/jobs/{job_id}/stop")
def stop_scan_job(project_id: int, job_id: int, db: Session = Depends(get_db)):
    """Stop a running job (kill the tool process)."""
    from app.runners.base import RUNNING_JOBS
    job = db.query(ScanJob).filter(ScanJob.project_id == project_id, ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status not in ("running", "pending"):
        return {"status": job.status, "message": "Job not running"}
    proc = RUNNING_JOBS.get(job_id)
    if proc:
        try:
            proc.kill()
        except Exception:
            pass
        if job_id in RUNNING_JOBS:
            del RUNNING_JOBS[job_id]
    job.status = "failed"
    job.error_message = "Stopped by user"
    from datetime import datetime
    job.finished_at = datetime.utcnow()
    item_id = get_item_id_by_runner_key(job.runner_key)
    if item_id:
        row = db.query(ChecklistStatus).filter(
            ChecklistStatus.project_id == project_id,
            ChecklistStatus.item_id == item_id,
        ).first()
        if row:
            row.status = "failed"
    db.commit()
    return {"status": "stopped"}


@app.delete("/api/projects/{project_id}/jobs/{job_id}")
def delete_scan_job(project_id: int, job_id: int, db: Session = Depends(get_db)):
    """Remove a job record (and its output file if present)."""
    job = db.query(ScanJob).filter(ScanJob.project_id == project_id, ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status in ("running", "pending"):
        raise HTTPException(400, "Cannot delete a running or pending job; stop it first")
    output_path = Path(job.output_path) if job.output_path else None
    db.delete(job)
    db.commit()
    if output_path and output_path.exists():
        try:
            output_path.unlink()
        except Exception:
            pass
    return {"deleted": job_id}


@app.get("/api/projects/{project_id}/jobs/{job_id}/output")
def get_scan_job_output(
    project_id: int,
    job_id: int,
    tail: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Return job output (live). If job is running, file may be growing. Use ?tail=N for last N bytes."""
    job = db.query(ScanJob).filter(ScanJob.project_id == project_id, ScanJob.id == job_id).first()
    if not job or not job.output_path:
        raise HTTPException(404, "Job or output not found")
    path = Path(job.output_path)
    if not path.exists():
        return "(Waiting for output...)\n"
    text = path.read_text(encoding="utf-8", errors="replace")
    if tail is not None and tail > 0 and len(text) > tail:
        text = "... [truncated]\n" + text[-tail:]
    return text


# Screenshots (gowitness output from web_host_enum)
@app.get("/api/projects/{project_id}/screenshots")
def list_screenshots(project_id: int, db: Session = Depends(get_db)):
    """List screenshots for a project (from gowitness); includes all files in screenshots folder."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    results_dir = Path("data/results") / str(project_id)
    screenshots_dir = results_dir / "screenshots"
    out = []
    seen = set()
    if (screenshots_dir / "manifest.json").exists():
        try:
            data = json.loads((screenshots_dir / "manifest.json").read_text())
            for s in data if isinstance(data, list) else []:
                fn = s.get("filename") or (s if isinstance(s, str) else None)
                if fn:
                    seen.add(fn)
                    out.append(s if isinstance(s, dict) else {"filename": fn, "url": ""})
        except Exception:
            pass
    for path in screenshots_dir.glob("*"):
        if path.is_file() and path.suffix.lower() in (".png", ".jpg", ".jpeg"):
            if path.name not in seen:
                seen.add(path.name)
                out.append({"filename": path.name, "url": ""})
    return out


@app.get("/api/projects/{project_id}/screenshots/files/{filename:path}")
def get_screenshot_file(project_id: int, filename: str, db: Session = Depends(get_db)):
    """Serve a screenshot image by filename (png or jpeg)."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    results_dir = Path("data/results") / str(project_id)
    file_path = results_dir / "screenshots" / filename
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(404, "Screenshot not found")
    try:
        file_path.resolve().relative_to(results_dir.resolve())
    except ValueError:
        raise HTTPException(404, "Screenshot not found")
    from fastapi.responses import FileResponse
    ext = file_path.suffix.lower()
    media_type = "image/jpeg" if ext in (".jpg", ".jpeg") else "image/png"
    return FileResponse(file_path, media_type=media_type)


@app.get("/api/projects/{project_id}/hosts")
def get_project_hosts(project_id: int, db: Session = Depends(get_db)):
    """Aggregated view of hosts with ports, screenshots, and findings for Hosts tab. Excluded hosts are filtered out."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    from app.hosts_aggregator import aggregate_hosts, canonical_host
    from app.config import settings
    results_dir = settings.results_dir / str(project_id)
    hosts = aggregate_hosts(project_id, results_dir)
    excluded = {row[0] for row in db.query(ProjectExcludedHost.host).filter(ProjectExcludedHost.project_id == project_id).all()}
    return [h for h in hosts if canonical_host(h.get("host") or "") not in excluded]


class ExcludeHostBody(BaseModel):
    host: str = ""


@app.post("/api/projects/{project_id}/hosts/exclude")
def exclude_project_host(project_id: int, body: ExcludeHostBody, db: Session = Depends(get_db)):
    """Exclude a host from the Hosts tab (e.g. out-of-scope). Uses canonical host (no port) for dedupe."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    from app.hosts_aggregator import canonical_host
    host = (body.host or "").strip()
    if not host:
        raise HTTPException(400, "host is required")
    canonical = canonical_host(host)
    existing = db.query(ProjectExcludedHost).filter(
        ProjectExcludedHost.project_id == project_id,
        ProjectExcludedHost.host == canonical,
    ).first()
    if not existing:
        db.add(ProjectExcludedHost(project_id=project_id, host=canonical))
        db.commit()
    return {"ok": True, "host": canonical}


# ---- Nessus / Tenable VM ----
@app.get("/api/nessus/configured")
def nessus_configured():
    """Whether Tenable API is configured (Nessus tab is usable)."""
    return {"configured": tenable_client.is_configured()}


@app.get("/api/projects/{project_id}/nessus/templates")
def nessus_list_templates(project_id: int, db: Session = Depends(get_db)):
    """List Nessus scan templates and policies (built-in + user-defined) for the create-scan dropdown."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not tenable_client.is_configured():
        raise HTTPException(503, "Tenable API is not configured")
    try:
        return tenable_client.list_templates_and_policies()
    except TenableAPIError as e:
        if e.status_code == 401:
            raise HTTPException(401, "Tenable API: Unauthorized. Check your API keys in .env.")
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/api/projects/{project_id}/nessus/scanners")
def nessus_list_scanners(project_id: int, db: Session = Depends(get_db)):
    """List Tenable scanners."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not tenable_client.is_configured():
        raise HTTPException(503, "Tenable API is not configured")
    try:
        return tenable_client.list_scanners()
    except TenableAPIError as e:
        if e.status_code == 401:
            raise HTTPException(401, "Tenable API: Unauthorized. Check your API keys in .env.")
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/api/projects/{project_id}/nessus/scans")
def nessus_list_scans(project_id: int, db: Session = Depends(get_db)):
    """List Tenable scans (proxy). Project is validated but scans are global. No cache so refresh shows current list."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not tenable_client.is_configured():
        raise HTTPException(503, "Tenable API is not configured (set FORSIGHT_TENABLE_ACCESS_KEY and SECRET_KEY)")
    try:
        data = tenable_client.list_scans()
        return JSONResponse(
            content=data,
            headers={"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"},
        )
    except TenableAPIError as e:
        if e.status_code == 401:
            raise HTTPException(401, "Tenable API: Unauthorized. Check FORSIGHT_TENABLE_ACCESS_KEY and FORSIGHT_TENABLE_SECRET_KEY in .env and that keys are valid in Tenable.io.")
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(502, str(e))


class NessusCreateScanBody(BaseModel):
    name: str
    template_uuid: str  # UUID for template, or "policy:123" to use policy id
    use_project_targets: bool = True
    text_targets: Optional[str] = None  # optional override; if use_project_targets, we append to project targets


@app.post("/api/projects/{project_id}/nessus/scans")
def nessus_create_scan(
    project_id: int,
    body: NessusCreateScanBody,
    db: Session = Depends(get_db),
):
    """Create a Tenable scan. Targets come from project ROE when use_project_targets is true."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not tenable_client.is_configured():
        raise HTTPException(503, "Tenable API is not configured")
    ips, domains = get_project_targets(p)
    targets_list = ips + domains
    if body.text_targets and body.text_targets.strip():
        # Optional extra targets (comma/newline separated)
        extra = [t.strip() for t in body.text_targets.replace("\n", ",").split(",") if t.strip()]
        targets_list = list(dict.fromkeys(targets_list + extra))
    text_targets = ",".join(targets_list) if targets_list else (body.text_targets or "")
    if not text_targets.strip():
        raise HTTPException(400, "No targets. Add IPs/domains in project ROE or in the targets field.")
    template_uuid: Optional[str] = None
    policy_id: Optional[int] = None
    if body.template_uuid.startswith("policy:"):
        try:
            policy_id = int(body.template_uuid.replace("policy:", "").strip())
        except ValueError:
            raise HTTPException(400, "Invalid policy id")
    else:
        template_uuid = body.template_uuid.strip() or None
    if not template_uuid and policy_id is None:
        raise HTTPException(400, "Select a template or policy.")
    try:
        return tenable_client.create_scan(
            name=body.name,
            text_targets=text_targets,
            template_uuid=template_uuid,
            policy_id=policy_id,
        )
    except TenableAPIError as e:
        if e.status_code == 401:
            raise HTTPException(401, "Tenable API: Unauthorized. Check your API keys in .env.")
        if e.status_code and 400 <= e.status_code < 500:
            detail = str(e)
            if e.response_text:
                try:
                    err_body = json.loads(e.response_text)
                    if isinstance(err_body, dict) and err_body.get("error"):
                        detail = err_body["error"]
                except Exception:
                    pass
            raise HTTPException(400, detail)
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/api/projects/{project_id}/nessus/scans/{scan_id}")
def nessus_get_scan(project_id: int, scan_id: int, db: Session = Depends(get_db)):
    """Get Tenable scan details."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not tenable_client.is_configured():
        raise HTTPException(503, "Tenable API is not configured")
    try:
        return tenable_client.get_scan(scan_id)
    except TenableAPIError as e:
        if e.status_code == 401:
            raise HTTPException(401, "Tenable API: Unauthorized. Check your API keys in .env.")
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(502, str(e))


class NessusLaunchBody(BaseModel):
    use_project_targets: bool = False


@app.post("/api/projects/{project_id}/nessus/scans/{scan_id}/launch")
def nessus_launch_scan(
    project_id: int,
    scan_id: int,
    body: NessusLaunchBody = Body(default=NessusLaunchBody()),
    db: Session = Depends(get_db),
):
    """Launch a Tenable scan. If use_project_targets is true, pass project IPs/domains as alt_targets."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not tenable_client.is_configured():
        raise HTTPException(503, "Tenable API is not configured")
    alt_targets = None
    if body.use_project_targets:
        ips, domains = get_project_targets(p)
        alt_targets = ips + domains
    try:
        data = tenable_client.launch_scan(scan_id, alt_targets=alt_targets)
        return data
    except TenableAPIError as e:
        if e.status_code == 401:
            raise HTTPException(401, "Tenable API: Unauthorized. Check your API keys in .env.")
        if e.status_code and 400 <= e.status_code < 500:
            detail = str(e)
            if e.response_text:
                try:
                    err_body = json.loads(e.response_text)
                    if isinstance(err_body, dict) and err_body.get("error"):
                        detail = err_body["error"]
                except Exception:
                    pass
            raise HTTPException(400, detail)
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/api/nessus/web-launch-available")
def nessus_web_launch_available():
    """
    Whether launch-via-web is available (Selenium + username/password).
    Returns open_url so frontend can offer "Open in Nessus" when web launch isn't used.
    """
    base = (settings.tenable_base_url or "").rstrip("/")
    has_creds = bool(settings.tenable_username and settings.tenable_password)
    selenium_ok = nessus_web_launch.is_available()
    return {
        "available": has_creds and selenium_ok,
        "open_url": f"{base}/#/scans/folders/my-scans" if base else None,
        "reason": None if (has_creds and selenium_ok) else (
            "Set FORSIGHT_TENABLE_USERNAME and FORSIGHT_TENABLE_PASSWORD for web launch."
            if not has_creds else "Selenium not installed (pip install selenium)."
        ),
    }


class NessusLaunchWebBody(BaseModel):
    scan_name: Optional[str] = None  # prefer finding row by name (ID may not be set until scan runs)


class NessusLaunchWebByNameBody(BaseModel):
    scan_name: str  # required: find row by name, click launch in that row (ID not needed until scan runs)


@app.post("/api/projects/{project_id}/nessus/launch-web")
def nessus_launch_scan_via_web_by_name(
    project_id: int,
    body: NessusLaunchWebByNameBody,
    db: Session = Depends(get_db),
):
    """
    Launch via Selenium: find the scan row by name (datatable tr data-name / td.scan-visible-name),
    then click the launch button in that row. The row's data-id is the scan id we're launching.
    """
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not settings.tenable_username or not settings.tenable_password:
        raise HTTPException(
            400,
            "Web launch requires FORSIGHT_TENABLE_USERNAME and FORSIGHT_TENABLE_PASSWORD",
        )
    if not nessus_web_launch.is_available():
        raise HTTPException(
            503,
            "Selenium is not installed. Install with: pip install selenium. Chrome or Chromium must be available.",
        )
    name = (body.scan_name or "").strip()
    if not name:
        raise HTTPException(400, "scan_name is required")
    try:
        result = nessus_web_launch.launch_scan_via_web(
            base_url=settings.tenable_base_url or "https://127.0.0.1:8834",
            username=settings.tenable_username,
            password=settings.tenable_password,
            scan_id=None,
            scan_name=name,
            verify_ssl=settings.tenable_verify_ssl,
        )
        return result
    except nessus_web_launch.NessusWebLaunchError as e:
        raise HTTPException(502, _sanitize_nessus_web_error(str(e)))


@app.post("/api/projects/{project_id}/nessus/scans/{scan_id}/launch-web")
def nessus_launch_scan_via_web(
    project_id: int,
    scan_id: int,
    body: Optional[NessusLaunchWebBody] = Body(None),
    db: Session = Depends(get_db),
):
    """Launch via Selenium: find row by scan_name in body, click launch in that row. Path scan_id is ignored."""
    scan_name = (body.scan_name or "").strip() if body else None
    if not scan_name:
        raise HTTPException(400, "scan_name required in body")
    return nessus_launch_scan_via_web_by_name(
        project_id=project_id,
        body=NessusLaunchWebByNameBody(scan_name=scan_name),
        db=db,
    )


class NessusDeleteWebBody(BaseModel):
    scan_name: Optional[str] = None  # prefer finding row by name


class NessusDeleteWebByNameBody(BaseModel):
    scan_name: str  # required: find row by name, click trash in that row


@app.post("/api/projects/{project_id}/nessus/delete-web")
def nessus_delete_scan_via_web_by_name(
    project_id: int,
    body: NessusDeleteWebByNameBody,
    db: Session = Depends(get_db),
):
    """Delete a Nessus scan via the web UI by scan name. Finds the row by name and clicks trash."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not settings.tenable_username or not settings.tenable_password:
        raise HTTPException(400, "Web delete requires FORSIGHT_TENABLE_USERNAME and FORSIGHT_TENABLE_PASSWORD")
    if not nessus_web_launch.is_available():
        raise HTTPException(503, "Selenium is not installed. Install with: pip install selenium.")
    name = (body.scan_name or "").strip()
    if not name:
        raise HTTPException(400, "scan_name is required")
    try:
        result = nessus_web_launch.delete_scan_via_web(
            base_url=settings.tenable_base_url or "https://127.0.0.1:8834",
            username=settings.tenable_username,
            password=settings.tenable_password,
            scan_id=None,
            scan_name=name,
            verify_ssl=settings.tenable_verify_ssl,
        )
        return result
    except nessus_web_launch.NessusWebLaunchError as e:
        raise HTTPException(502, _sanitize_nessus_web_error(str(e)))


@app.post("/api/projects/{project_id}/nessus/scans/{scan_id}/delete-web")
def nessus_delete_scan_via_web(
    project_id: int,
    scan_id: int,
    body: Optional[NessusDeleteWebBody] = Body(None),
    db: Session = Depends(get_db),
):
    """Delete via web UI: find row by scan_name in body, click trash in that row. Prefer POST /nessus/delete-web."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not settings.tenable_username or not settings.tenable_password:
        raise HTTPException(400, "Web delete requires FORSIGHT_TENABLE_USERNAME and FORSIGHT_TENABLE_PASSWORD")
    if not nessus_web_launch.is_available():
        raise HTTPException(503, "Selenium is not installed. Install with: pip install selenium.")
    scan_name = (body.scan_name or "").strip() if body else None
    if not scan_name:
        raise HTTPException(400, "scan_name required in body (find row by name, click trash in that row)")
    try:
        result = nessus_web_launch.delete_scan_via_web(
            base_url=settings.tenable_base_url or "https://127.0.0.1:8834",
            username=settings.tenable_username,
            password=settings.tenable_password,
            scan_id=None,
            scan_name=scan_name,
            verify_ssl=settings.tenable_verify_ssl,
        )
        return result
    except nessus_web_launch.NessusWebLaunchError as e:
        raise HTTPException(502, _sanitize_nessus_web_error(str(e)))


class NessusCreateScanWebBody(BaseModel):
    name: str
    template_key: str = "advanced"  # e.g. "advanced", "Basic", "Web App" – matched in Nessus UI
    use_project_targets: bool = True
    text_targets: Optional[str] = None  # optional override or extra; if use_project_targets, merged with project targets


@app.post("/api/projects/{project_id}/nessus/create-scan-web")
def nessus_create_scan_via_web(
    project_id: int,
    body: NessusCreateScanWebBody,
    db: Session = Depends(get_db),
):
    """Create a new Nessus scan via the web UI (Selenium): New Scan → template → name → targets."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not settings.tenable_username or not settings.tenable_password:
        raise HTTPException(
            400,
            "Web create requires FORSIGHT_TENABLE_USERNAME and FORSIGHT_TENABLE_PASSWORD",
        )
    if not nessus_web_launch.is_available():
        raise HTTPException(
            503,
            "Selenium is not installed. Install with: pip install selenium.",
        )
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(400, "Scan name is required")
    ips, domains = get_project_targets(p)
    targets_list = ips + domains
    if body.text_targets and body.text_targets.strip():
        extra = [t.strip() for t in body.text_targets.replace("\n", ",").split(",") if t.strip()]
        targets_list = list(dict.fromkeys(targets_list + extra))
    text_targets = "\n".join(targets_list) if targets_list else (body.text_targets or "").strip()
    if not text_targets:
        raise HTTPException(400, "No targets. Add IPs/domains in project ROE or in the targets field.")
    try:
        result = nessus_web_launch.create_scan_via_web(
            base_url=settings.tenable_base_url or "https://127.0.0.1:8834",
            username=settings.tenable_username,
            password=settings.tenable_password,
            scan_name=name,
            targets_text=text_targets,
            template_key=body.template_key or "advanced",
            verify_ssl=settings.tenable_verify_ssl,
        )
        return result
    except nessus_web_launch.NessusWebLaunchError as e:
        raise HTTPException(502, _sanitize_nessus_web_error(str(e)))


class NessusExportBody(BaseModel):
    format: str = "nessus"


@app.post("/api/projects/{project_id}/nessus/scans/{scan_id}/export")
def nessus_export_scan(
    project_id: int,
    scan_id: int,
    body: NessusExportBody = Body(default=NessusExportBody()),
    db: Session = Depends(get_db),
):
    """Request scan export (async). Returns file id to poll status and download."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not tenable_client.is_configured():
        raise HTTPException(503, "Tenable API is not configured")
    try:
        return tenable_client.export_scan(scan_id, format=body.format)
    except TenableAPIError as e:
        if e.status_code == 401:
            raise HTTPException(401, "Tenable API: Unauthorized. Check your API keys in .env.")
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/api/projects/{project_id}/nessus/scans/{scan_id}/export/{file_id}/status")
def nessus_export_status(
    project_id: int,
    scan_id: int,
    file_id: int,
    db: Session = Depends(get_db),
):
    """Poll export job status until ready."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not tenable_client.is_configured():
        raise HTTPException(503, "Tenable API is not configured")
    try:
        return tenable_client.export_status(scan_id, file_id)
    except TenableAPIError as e:
        if e.status_code == 401:
            raise HTTPException(401, "Tenable API: Unauthorized. Check your API keys in .env.")
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/api/projects/{project_id}/nessus/scans/{scan_id}/export/{file_id}/download")
def nessus_export_download(
    project_id: int,
    scan_id: int,
    file_id: int,
    db: Session = Depends(get_db),
):
    """Download exported scan file."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not tenable_client.is_configured():
        raise HTTPException(503, "Tenable API is not configured")
    try:
        content = tenable_client.export_download(scan_id, file_id)
    except TenableAPIError as e:
        if e.status_code == 401:
            raise HTTPException(401, "Tenable API: Unauthorized. Check your API keys in .env.")
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(502, str(e))
    ext = "nessus"  # or from query param if we add format
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-export.{ext}"'},
    )


def _nessus_imports_path(project_id: int) -> Path:
    return get_project_results_dir(project_id) / "nessus_imports.json"


def _load_nessus_imports(project_id: int) -> dict:
    path = _nessus_imports_path(project_id)
    if not path.exists():
        return {"scans": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and "scans" in data else {"scans": {}}
    except Exception:
        return {"scans": {}}


def _save_nessus_imports(project_id: int, data: dict) -> None:
    path = _nessus_imports_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


@app.post("/api/projects/{project_id}/nessus/import/{scan_id}")
def nessus_import_scan_results(project_id: int, scan_id: int, db: Session = Depends(get_db)):
    """Export scan from Nessus, parse results, and store in project. Use this to pull findings into ForSight."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    if not tenable_client.is_configured():
        raise HTTPException(503, "Tenable API is not configured")
    try:
        export_resp = tenable_client.export_scan(scan_id, format="nessus")
        file_id = export_resp.get("file")
        if file_id is None:
            raise HTTPException(502, "Nessus export did not return a file id")
        for _ in range(60):
            status_resp = tenable_client.export_status(scan_id, file_id)
            if status_resp.get("status") == "ready":
                break
            time.sleep(2)
        else:
            raise HTTPException(504, "Nessus export timed out")
        content = tenable_client.export_download(scan_id, file_id)
    except TenableAPIError as e:
        if e.status_code == 401:
            raise HTTPException(401, "Tenable API: Unauthorized. Check your API keys in .env.")
        raise HTTPException(502, str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, str(e))

    try:
        parsed = parse_nessus_xml(content)
    except Exception as e:
        raise HTTPException(400, f"Failed to parse Nessus export: {e}")

    scan_name = parsed.get("scan_name") or f"Scan {scan_id}"
    hosts = parsed.get("hosts") or []
    vulns_count = sum(len(h.get("vulns") or []) for h in hosts)

    data = _load_nessus_imports(project_id)
    data["scans"][str(scan_id)] = {
        "scan_id": scan_id,
        "scan_name": scan_name,
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "hosts": hosts,
        "hosts_count": len(hosts),
        "vulns_count": vulns_count,
    }
    _save_nessus_imports(project_id, data)

    return {
        "scan_id": scan_id,
        "scan_name": scan_name,
        "hosts_count": len(hosts),
        "vulns_count": vulns_count,
        "imported_at": data["scans"][str(scan_id)]["imported_at"],
    }


@app.get("/api/projects/{project_id}/nessus/imports")
def nessus_list_imports(project_id: int, db: Session = Depends(get_db)):
    """List imported Nessus scan results for this project."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    data = _load_nessus_imports(project_id)
    scans = []
    for sid, s in data.get("scans", {}).items():
        scans.append({
            "scan_id": int(sid) if str(sid).isdigit() else sid,
            "scan_name": s.get("scan_name", ""),
            "imported_at": s.get("imported_at", ""),
            "hosts_count": s.get("hosts_count", len(s.get("hosts", []))),
            "vulns_count": s.get("vulns_count", 0),
        })
    return {"scans": scans}


@app.get("/api/projects/{project_id}/nessus/imports/{scan_id}")
def nessus_get_import(project_id: int, scan_id: int, db: Session = Depends(get_db)):
    """Get full imported scan results (hosts and vulns) for Nessus tab detail view."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    data = _load_nessus_imports(project_id)
    scan_data = data.get("scans", {}).get(str(scan_id))
    if not scan_data:
        raise HTTPException(404, "Imported scan not found")
    return scan_data


@app.delete("/api/projects/{project_id}/nessus/imports/{scan_id}")
def nessus_delete_import(project_id: int, scan_id: int, db: Session = Depends(get_db)):
    """Remove an imported scan from this project."""
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    data = _load_nessus_imports(project_id)
    if str(scan_id) in data.get("scans", {}):
        del data["scans"][str(scan_id)]
        _save_nessus_imports(project_id, data)
    return {"deleted": scan_id}


@app.get("/api/health")
def health():
    """Server health for Settings."""
    return {"status": "ok", "service": "ForSight"}


# ---- Roadmap ----
ROADMAP_SEED = [
    {"title": "Nessus API integration", "description": "Import scan results from Tenable Nessus via API; map findings to hosts and checklist.", "status": "planned", "category": "Integrations", "sort_order": 0},
    {"title": "Burp Suite integration", "description": "Import Burp project/scan data; link issues to hosts.", "status": "planned", "category": "Integrations", "sort_order": 1},
    {"title": "Report templates", "description": "Export engagements to PDF/Word with configurable templates and executive summaries.", "status": "planned", "category": "Reporting", "sort_order": 2},
    {"title": "Scheduled scans", "description": "Schedule recurring nmap or web scans per project.", "status": "planned", "category": "Automation", "sort_order": 3},
    {"title": "Multi-user & roles", "description": "User accounts, roles (viewer/operator/admin), and per-project access.", "status": "planned", "category": "Platform", "sort_order": 4},
    {"title": "Custom checklist phases", "description": "Let users define custom phases and tool runners.", "status": "planned", "category": "Platform", "sort_order": 5},
]


def seed_roadmap_if_empty(db: Session) -> None:
    if db.query(RoadmapItem).count() > 0:
        return
    for item in ROADMAP_SEED:
        db.add(RoadmapItem(**item))
    db.commit()


@app.get("/api/roadmap", response_model=List[RoadmapItemOut])
def list_roadmap(db: Session = Depends(get_db)):
    """List planned future updates for the project."""
    seed_roadmap_if_empty(db)
    items = db.query(RoadmapItem).order_by(RoadmapItem.sort_order, RoadmapItem.id).all()
    # Deduplicate by title (in case seed ran twice from concurrent requests)
    seen_titles: set[str] = set()
    out = []
    for x in items:
        if x.title not in seen_titles:
            seen_titles.add(x.title)
            out.append(RoadmapItemOut.model_validate(x))
    return out


# ---- Feature requests & bug tracking ----
@app.get("/api/feedback", response_model=List[FeedbackOut])
def list_feedback(kind: Optional[str] = None, db: Session = Depends(get_db)):
    """List feature requests and/or bug reports. kind: 'feature' | 'bug' or omit for all."""
    q = db.query(Feedback).order_by(Feedback.created_at.desc())
    if kind in ("feature", "bug"):
        q = q.filter(Feedback.kind == kind)
    items = q.all()
    return [FeedbackOut.model_validate(x) for x in items]


@app.post("/api/feedback", response_model=FeedbackOut)
def create_feedback(body: FeedbackCreate, db: Session = Depends(get_db)):
    """Submit a feature request or bug report."""
    if body.kind not in ("feature", "bug"):
        raise HTTPException(400, "kind must be 'feature' or 'bug'")
    item = Feedback(kind=body.kind, title=body.title, description=body.description or None)
    db.add(item)
    db.commit()
    db.refresh(item)
    return FeedbackOut.model_validate(item)


@app.get("/api/projects/{project_id}/download")
def download_all_outputs(project_id: int, db: Session = Depends(get_db)):
    """Download all tool outputs for the project as a zip file."""
    import io
    import zipfile
    from fastapi.responses import Response
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    results_dir = Path("data/results") / str(project_id)
    if not results_dir.exists():
        raise HTTPException(404, "No outputs yet for this project")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in results_dir.rglob("*"):
            if f.is_file():
                arcname = f.relative_to(results_dir.parent)
                zf.write(f, arcname)
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="forsight-project-{project_id}-outputs.zip"'},
    )
