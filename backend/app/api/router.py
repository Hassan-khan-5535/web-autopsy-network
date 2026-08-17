from fastapi import APIRouter

from app.api.routes.health import router as health_router
from app.api.routes.scans import router as scans_router
from app.api.routes.websites import router as websites_router
from app.api.routes.workers import router as workers_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["system"])
api_router.include_router(scans_router, prefix="/v1/scans", tags=["scans"])
api_router.include_router(websites_router, prefix="/v1", tags=["websites"])
api_router.include_router(workers_router, prefix="/v1", tags=["workers"])
