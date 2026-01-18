"""
Security middleware for HTTP headers and request validation.
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.

    Implements OWASP security header recommendations.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)

        # Content Security Policy
        # Relaxed CSP for test page (allows inline scripts)
        # Strict CSP for API endpoints
        if request.url.path == "/test":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Enable XSS filter (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions Policy (formerly Feature-Policy)
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )

        # HSTS (only in production with HTTPS)
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Cache control for API responses
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"

        return response


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for request validation and sanitization.
    """

    # Maximum request body size (10 MB)
    MAX_BODY_SIZE = 10 * 1024 * 1024

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Check content length
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.MAX_BODY_SIZE:
                    return Response(
                        content='{"detail": "Request body too large"}',
                        status_code=413,
                        media_type="application/json",
                    )
            except ValueError:
                pass

        return await call_next(request)
