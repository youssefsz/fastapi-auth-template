"""
FastAPI Application Factory.

Creates and configures the FastAPI application with all middleware and routes.
"""

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app import __version__
from app.api.v1.router import api_router
from app.core.config import settings
from app.db.session import close_db, init_db
from app.middleware.rate_limit import limiter
from app.middleware.security import RequestValidationMiddleware, SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan handler.

    Handles startup and shutdown events.
    """
    # Startup
    # Initialize database tables (in production, use Alembic instead)
    if settings.is_development:
        await init_db()

    yield

    # Shutdown
    await close_db()


def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title=settings.app_name,
        description="""
## Production-Ready Authentication API

A secure, scalable authentication system built with FastAPI.

### Features

- **JWT Authentication**: Access tokens + refresh tokens with secure rotation
- **Google OAuth 2.0**: Social login with account linking
- **Security**: Argon2 password hashing, rate limiting, brute-force protection
- **Async-first**: Built on async PostgreSQL and SQLAlchemy

### Authentication Flow

1. **Register** or **Login** to get tokens
2. Use the **access token** in the `Authorization: Bearer <token>` header
3. When access token expires, use **refresh token** to get new tokens
4. **Logout** to revoke tokens

### Rate Limits

- General API: 60 requests/minute
- Auth endpoints: 5 requests/minute
- Password reset: 3 requests/minute
        """,
        version=__version__,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )

    # Add rate limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Add CORS middleware
    # Handle wildcard CORS for development
    cors_origins = settings.cors_origins_list
    allow_all = "*" in cors_origins or settings.cors_origins == "*"
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if allow_all else cors_origins,
        allow_credentials=not allow_all,  # Cannot use credentials with '*'
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )

    # Add security middleware
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestValidationMiddleware)

    # Include API router
    app.include_router(api_router, prefix="/api/v1")

    # Root endpoint
    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "name": settings.app_name,
            "version": __version__,
            "docs": "/docs" if settings.debug else "Disabled in production",
            "test": "/test",
        }

    # Test page endpoint
    @app.get("/test", include_in_schema=False, response_class=HTMLResponse)
    async def test_page() -> HTMLResponse:
        """Serve the authentication test page."""
        import os
        static_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "test.html")
        with open(static_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        """Handle uncaught exceptions."""
        # Log the error in production
        if settings.is_production:
            import logging

            logging.error(f"Unhandled exception: {exc}", exc_info=True)

        # Don't expose internal errors in production
        if settings.is_production:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error"},
            )

        # In development, return the actual error
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": str(exc)},
        )

    return app


# Create application instance
app = create_application()
