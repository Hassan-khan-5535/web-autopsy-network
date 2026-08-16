from collections.abc import Generator
from dataclasses import dataclass

from collections.abc import Generator
from fastapi import Header, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import SessionLocal

@dataclass(frozen=True)
class AuthIdentity:
    """Future authentication principal contract; no login or token issuer exists in Phase 1."""

    subject: str


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_configured_identity(authorization: str | None = Header(default=None)) -> AuthIdentity:
    """Reserve an auth dependency without accepting unsigned or unverified tokens."""

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Authentication flow is not implemented in Phase 1",
    )
