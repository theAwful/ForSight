"""Pydantic schemas for API."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class ProjectCreate(BaseModel):
    name: str


class ProjectOut(BaseModel):
    id: int
    name: str
    created_at: datetime
    roe_filename: Optional[str] = None
    targets_summary: Optional[dict] = None

    class Config:
        from_attributes = True


class ChecklistItemOut(BaseModel):
    id: str
    phase: str
    description: str
    runner_key: Optional[str] = None
    tools: List[str] = []
    status: str = "not_started"
    notes: Optional[str] = None


class ChecklistPhaseOut(BaseModel):
    phase: str
    items: List[ChecklistItemOut]


class ScanJobOut(BaseModel):
    id: int
    project_id: int
    runner_key: str
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    output_path: Optional[str] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class ROEUploadResult(BaseModel):
    project_id: int
    filename: str
    ips_count: int
    domains_count: int


class RoadmapItemOut(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    status: str
    category: Optional[str] = None
    sort_order: int
    created_at: datetime

    class Config:
        from_attributes = True


class RoadmapItemCreate(BaseModel):
    title: str
    description: Optional[str] = None
    status: str = "planned"
    category: Optional[str] = None
    sort_order: int = 0


class FeedbackOut(BaseModel):
    id: int
    kind: str
    title: str
    description: Optional[str] = None
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class FeedbackCreate(BaseModel):
    kind: str  # feature, bug
    title: str
    description: Optional[str] = None
