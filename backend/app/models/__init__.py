"""Future SQLAlchemy domain models are added here through Alembic migrations."""

from app.models.base import Base
from app.models.scan import Website, Scan, Page, HTTPResponse, Header, Resource, Observation

__all__ = [
    "Base",
    "Website",
    "Scan",
    "Page",
    "HTTPResponse",
    "Header",
    "Resource",
    "Observation",
]
