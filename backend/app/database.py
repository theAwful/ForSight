"""Database session and dependency."""

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.models import Base, ChecklistStatus, Project, ProjectExcludedHost, ScanJob, RoadmapItem, Feedback

# Ensure data dir exists
settings.data_dir.mkdir(parents=True, exist_ok=True)
settings.uploads_dir.mkdir(parents=True, exist_ok=True)
settings.results_dir.mkdir(parents=True, exist_ok=True)

_db_file = (settings.data_dir / "forsight.db").resolve()
DATABASE_URL = URL.create(drivername="sqlite", database=str(_db_file))
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_database():
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
