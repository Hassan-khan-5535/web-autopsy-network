"""Future SQLAlchemy domain models are added here through Alembic migrations."""

from app.models.base import Base
from app.models.scan import (
    Header,
    HTTPResponse,
    Observation,
    Page,
    PageLink,
    Resource,
    Scan,
    Website,
)

__all__ = [
    "Base",
    "Website",
    "Scan",
    "Page",
    "PageLink",
    "HTTPResponse",
    "Header",
    "Resource",
    "Observation",
]
