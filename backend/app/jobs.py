"""Background job execution for scan runners."""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from sqlalchemy.orm import Session

from app.checklist import get_item_id_by_runner_key
from app.config import settings
from app.models import ChecklistStatus, Project, ScanJob
from app.roe import parse_roe_content
from app.runners import get_runner


def get_project_targets(project: Project) -> tuple[List[str], List[str]]:
    """Return (ips, domains) from project ROE."""
    if project.targets_raw:
        data = json.loads(project.targets_raw)
        return data.get("ips", []), data.get("domains", [])
    return [], []


def get_project_results_dir(project_id: int) -> Path:
    return settings.results_dir / str(project_id)


def init_job_output_file(stream_path: Path, runner_key: str, ips: List[str], domains: List[str]) -> None:
    """Create the job output file with a header so the Output tab can show content immediately."""
    header = f"=== {runner_key} ===\nTargets: {len(ips)} IPs, {len(domains)} domains\n"
    stream_path.write_text(header, encoding="utf-8")


async def run_runner(
    runner_key: str,
    project: Project,
    job: Optional[ScanJob] = None,
    db: Optional[Session] = None,
    run_options: Optional[dict] = None,
) -> Optional[ScanJob]:
    """Run the runner and optionally update an existing ScanJob."""
    if job is None and db is not None:
        job = ScanJob(
            project_id=project.id,
            runner_key=runner_key,
            status="running",
            started_at=datetime.utcnow(),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
    elif job is not None and db is not None:
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()
        db.refresh(job)
    results_dir = get_project_results_dir(project.id)
    results_dir.mkdir(parents=True, exist_ok=True)
    ips, domains = get_project_targets(project)
    # Live output: create stream file upfront so GET output can read while job runs
    stream_path = results_dir / f"job_{job.id}.txt" if job else None
    if job and db:
        job.output_path = str(stream_path)
        db.commit()
        db.refresh(job)
    # Only write header if file doesn't exist (main.py may have already created it for live output)
    if stream_path is not None and (not stream_path.exists() or stream_path.stat().st_size == 0):
        init_job_output_file(stream_path, runner_key, ips, domains)
    runner = get_runner(runner_key)
    if not runner:
        if job and db:
            job.status = "failed"
            job.error_message = f"Unknown runner: {runner_key}"
            job.finished_at = datetime.utcnow()
            db.commit()
        return job
    try:
        code, stdout, stderr, output_path = await runner(
            project_id=project.id,
            ips=ips,
            domains=domains,
            results_dir=results_dir,
            stream_path=stream_path,
            job_id=job.id if job else None,
            **(run_options or {}),
        )
        if job and db:
            job.status = "completed" if code == 0 else "failed"
            job.finished_at = datetime.utcnow()
            job.output_path = str(output_path) if output_path else None
            if stderr and code != 0:
                job.error_message = stderr[:2000]
            # Update checklist item for this runner to completed/failed
            item_id = get_item_id_by_runner_key(runner_key)
            if item_id:
                row = db.query(ChecklistStatus).filter(
                    ChecklistStatus.project_id == project.id,
                    ChecklistStatus.item_id == item_id,
                ).first()
                if row:
                    row.status = "completed" if code == 0 else "failed"
            db.commit()
    except Exception as e:
        if job and db:
            job.status = "failed"
            job.finished_at = datetime.utcnow()
            job.error_message = str(e)[:2000]
            item_id = get_item_id_by_runner_key(runner_key)
            if item_id:
                row = db.query(ChecklistStatus).filter(
                    ChecklistStatus.project_id == project.id,
                    ChecklistStatus.item_id == item_id,
                ).first()
                if row:
                    row.status = "failed"
            db.commit()
    return job


def run_runner_sync(
    runner_key: str,
    project: Project,
    job: Optional[ScanJob] = None,
    db: Optional[Session] = None,
    run_options: Optional[dict] = None,
) -> Optional[ScanJob]:
    """Synchronous wrapper for run_runner (for background thread)."""
    return asyncio.run(run_runner(runner_key, project, job=job, db=db, run_options=run_options))
