from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.core.db import get_db
from src.api.core.settings import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


# PUBLIC_INTERFACE
def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


# PUBLIC_INTERFACE
def verify_password(password: str, password_hash: str) -> bool:
    """Verify plaintext password vs hashed password."""
    return pwd_context.verify(password, password_hash)


def _create_token(sub: str, token_type: str, expires_delta: timedelta) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "iss": "tickety",
        "sub": sub,
        "typ": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    settings = get_settings()
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


# PUBLIC_INTERFACE
def create_access_token(user_id: str) -> str:
    """Create a short-lived access token for user_id."""
    settings = get_settings()
    return _create_token(
        sub=user_id,
        token_type="access",
        expires_delta=timedelta(minutes=settings.jwt_access_token_expires_minutes),
    )


# PUBLIC_INTERFACE
def create_refresh_token(user_id: str) -> str:
    """Create a longer-lived refresh token for user_id."""
    settings = get_settings()
    return _create_token(
        sub=user_id,
        token_type="refresh",
        expires_delta=timedelta(days=settings.jwt_refresh_token_expires_days),
    )


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


# PUBLIC_INTERFACE
async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return current user dict from JWT Bearer token.

    Raises 401 if missing/invalid; raises 403 if user is inactive.
    """
    if creds is None or not creds.credentials:
        raise _unauthorized()

    settings = get_settings()
    try:
        payload = jwt.decode(
            creds.credentials, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
    except jwt.PyJWTError:
        raise _unauthorized("Invalid token")

    if payload.get("typ") != "access":
        raise _unauthorized("Invalid token type")

    user_id = payload.get("sub")
    if not user_id:
        raise _unauthorized("Invalid token subject")

    res = await db.execute(
        text(
            """
            SELECT id, email, first_name, last_name, is_active, is_email_verified, created_at
            FROM users
            WHERE id = :user_id
            """
        ),
        {"user_id": user_id},
    )
    row = res.mappings().first()
    if not row:
        raise _unauthorized("User not found")
    if not row["is_active"]:
        raise HTTPException(status_code=403, detail="User is inactive")

    return dict(row)


# PUBLIC_INTERFACE
async def require_role(
    role_name: str,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Ensure current user has the given role (RBAC).

    Usage:
      Depends(lambda: require_role('admin'))
    """
    res = await db.execute(
        text(
            """
            SELECT 1
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = :user_id AND r.name = :role_name
            """
        ),
        {"user_id": current_user["id"], "role_name": role_name},
    )
    if res.first() is None:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return current_user
