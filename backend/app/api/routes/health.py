from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.database import check_database_connection

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    service: str
    database: str
    environment: str


@router.get("/health", response_model=HealthResponse)
def health() -> JSONResponse:
    settings = get_settings()
    database_connected = check_database_connection()
    payload = HealthResponse(
        status="ok" if database_connected else "degraded",
        service="web-autopsy-network-api",
        database="connected" if database_connected else "unavailable",
        environment=settings.app_env,
    )
    return JSONResponse(
        status_code=(
            status.HTTP_200_OK if database_connected else status.HTTP_503_SERVICE_UNAVAILABLE
        ),
        content=payload.model_dump(),
    )
