"""Future SQLAlchemy domain models are added here through Alembic migrations."""

from app.models.base import Base
from app.models.scan import (
    AccessibilityFinding,
    AIInterpretation,
    ApiEndpoint,
    ContentFinding,
    Dependency,
    Header,
    HTTPResponse,
    Observation,
    Page,
    PageLink,
    PerformanceMetric,
    Resource,
    Scan,
    SecurityFinding,
    Technology,
    TechnologyEvidence,
    Website,
)

__all__ = [
    "Base",
    "Website",
    "Scan",
    "Page",
    "PageLink",
    "Technology",
    "TechnologyEvidence",
    "HTTPResponse",
    "Header",
    "Resource",
    "Observation",
    "Dependency",
    "ApiEndpoint",
    "SecurityFinding",
    "PerformanceMetric",
    "AccessibilityFinding",
    "ContentFinding",
    "AIInterpretation",
]

