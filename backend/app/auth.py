"""Authentication: session-based login with bcrypt password hashing."""

from fastapi import HTTPException, Request

from passlib.context import CryptContext

from app.config import settings

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

# Default user forsight/forsight: hash computed once at load
_DEFAULT_HASH = pwd_ctx.hash("forsight") if not settings.default_password_hash else settings.default_password_hash


def verify_password(plain: str, stored_hash: str) -> bool:
    """Verify plain password against stored bcrypt hash."""
    if not plain or not stored_hash:
        return False
    try:
        return pwd_ctx.verify(plain, stored_hash)
    except Exception:
        return False


def verify_credentials(username: str, password: str) -> bool:
    """Check username and password against default user (and optional config hash)."""
    if not username or not password:
        return False
    if username.strip().lower() != settings.default_username.strip().lower():
        return False
    return verify_password(password, _DEFAULT_HASH)


def get_current_user(request: Request) -> str:
    """Dependency: return username from session or raise 401."""
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return username
