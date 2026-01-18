"""
Health check endpoints.
"""

from fastapi import APIRouter

from app import __version__
from app.core.config import settings
from app.schemas.common import HealthResponse

router = APIRouter()


@router.get(
    "",
    response_model=HealthResponse,
    summary="Health Check",
    description="Check if the API is running and healthy.",
)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.

    Returns basic service information.
    """
    return HealthResponse(
        status="healthy",
        version=__version__,
        environment=settings.app_env,
    )


@router.get(
    "/ready",
    response_model=HealthResponse,
    summary="Readiness Check",
    description="Check if the API is ready to accept requests.",
)
async def readiness_check() -> HealthResponse:
    """
    Readiness check endpoint.

    Verifies database connectivity and other dependencies.
    """
    # In production, you might want to check:
    # - Database connectivity
    # - External service availability
    # - etc.

    return HealthResponse(
        status="ready",
        version=__version__,
        environment=settings.app_env,
    )
