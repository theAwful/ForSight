"""Tool management API router.

Endpoints:
    GET  /api/tools/status            — all tools
    GET  /api/tools/status/{key}      — single tool
    PATCH /api/tools/{key}/path       — update binary path (in-memory only)

Auth is enforced at the app level via AuthRequiredMiddleware.
No rate limiting needed — these are infrequent admin/operator actions.
"""

import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.tool_catalog import TOOL_CATALOG, check_all_tools, check_tool_status, update_tool_path

router = APIRouter(prefix="/api/tools", tags=["tools"])

# Shell metacharacters that must never appear in a binary path
_SHELL_METACHAR_RE = re.compile(r'[;&|`$<>()\n\r\'"\\]')


class UpdatePathBody(BaseModel):
    path: str


@router.get("/status")
def get_all_tool_status():
    """Return health status (binary found, version string) for all configured tools."""
    return check_all_tools()


@router.get("/status/{tool_key}")
def get_single_tool_status(tool_key: str):
    """Return health status for one tool by key."""
    if tool_key not in TOOL_CATALOG:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown tool key: {tool_key!r}. Valid keys: {sorted(TOOL_CATALOG.keys())}",
        )
    return check_tool_status(tool_key)


@router.patch("/{tool_key}/path")
def update_tool_binary_path(tool_key: str, body: UpdatePathBody):
    """
    Update the binary path for a tool (in-memory only; resets on backend restart).

    To persist permanently, set FORSIGHT_{TOOL_KEY_UPPER}_PATH in your .env file.
    """
    if tool_key not in TOOL_CATALOG:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown tool key: {tool_key!r}.",
        )

    path = body.path.strip()
    if not path:
        raise HTTPException(status_code=400, detail="path cannot be empty.")

    if _SHELL_METACHAR_RE.search(path):
        raise HTTPException(
            status_code=400,
            detail=(
                "Path must be a plain file path, not a shell expression. "
                "Remove any shell metacharacters (; & | ` $ < > ( ) quotes backslashes)."
            ),
        )

    if len(path) > 500:
        raise HTTPException(status_code=400, detail="Path is too long (max 500 characters).")

    try:
        update_tool_path(tool_key, path)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))

    # Return fresh status after the update
    return check_tool_status(tool_key)
