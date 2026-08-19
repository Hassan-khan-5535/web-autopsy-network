import logging
from time import perf_counter

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging

settings = get_settings()
settings.validate_production_security()
configure_logging(settings.log_level)
logger = logging.getLogger("web_autopsy.api")

app = FastAPI(
    title=settings.app_name,
    version="0.15.0",
    description="Authorization-gated continuous web security assessment platform with persisted evidence, posture reporting, and export controls.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,

    allow_methods=["*"],
    allow_headers=["*"],
)



@app.middleware("http")
async def log_request(request: Request, call_next):
    started_at = perf_counter()
    response = await call_next(request)
    logger.info(
        "request_completed",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": round((perf_counter() - started_at) * 1000, 2),
        },
    )
    return response


app.include_router(api_router)
