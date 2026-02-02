"""SQLAlchemy models for projects, ROE, and scan results."""

from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Project(Base):
    """An engagement/project with a name and optional ROE."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    roe_filename: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    roe_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    targets_raw: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Parsed IPs/domains as JSON list

    scan_jobs: Mapped[list["ScanJob"]] = relationship("ScanJob", back_populates="project")
    checklist_status: Mapped[list["ChecklistStatus"]] = relationship(
        "ChecklistStatus", back_populates="project"
    )
    excluded_hosts: Mapped[list["ProjectExcludedHost"]] = relationship(
        "ProjectExcludedHost", back_populates="project", cascade="all, delete-orphan"
    )


class ProjectExcludedHost(Base):
    """Hosts excluded from the Hosts tab for a project (e.g. out-of-scope)."""

    __tablename__ = "project_excluded_hosts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False)
    host: Mapped[str] = mapped_column(Text, nullable=False)  # canonical host (no port for dedupe)

    project: Mapped["Project"] = relationship("Project", back_populates="excluded_hosts")

    __table_args__ = (UniqueConstraint("project_id", "host", name="uq_project_excluded_host"),)


class ScanJob(Base):
    """A single scan run (e.g. nmap, subfinder) for a project."""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False)
    runner_key: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, default="pending")  # pending, running, completed, failed
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    output_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    project: Mapped["Project"] = relationship("Project", back_populates="scan_jobs")


class ChecklistStatus(Base):
    """Per-project status for each checklist item (not_started, in_progress, completed, skipped)."""

    __tablename__ = "checklist_status"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False)
    item_id: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, default="not_started")
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    project: Mapped["Project"] = relationship("Project", back_populates="checklist_status")


class RoadmapItem(Base):
    """Planned future updates for the project (e.g. Nessus API, report templates)."""

    __tablename__ = "roadmap"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, default="planned")  # planned, in_progress, done
    category: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # e.g. integrations, reporting
    sort_order: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Feedback(Base):
    """Feature requests and bug reports from users."""

    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # feature, bug
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, default="open")  # open, in_progress, done
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


def get_engine(db_path: str = "sqlite:///./forsight.db"):
    return create_engine(db_path, connect_args={"check_same_thread": False})


def init_db(engine=None):
    if engine is None:
        engine = get_engine()
    Base.metadata.create_all(engine)
    return engine
