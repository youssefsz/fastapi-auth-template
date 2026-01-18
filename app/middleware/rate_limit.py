"""
Rate limiting middleware using SlowAPI with in-memory backend.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings


def get_real_client_ip(request) -> str:
    """
    Get real client IP, considering proxy headers.

    Args:
        request: FastAPI/Starlette request

    Returns:
        Client IP address
    """
    # Check for forwarded IP (behind proxy/load balancer)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first (client)
        return forwarded_for.split(",")[0].strip()

    # Check for real-ip header (some proxies use this)
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip

    # Fall back to direct client IP
    return get_remote_address(request)


# Create limiter with in-memory storage (no Redis required)
limiter = Limiter(
    key_func=get_real_client_ip,
    default_limits=[f"{settings.rate_limit_per_minute}/minute"],
    storage_uri="memory://",  # In-memory storage
)


# Specific rate limits for auth endpoints (more restrictive)
AUTH_RATE_LIMIT = "5/minute"  # 5 requests per minute for login/register
PASSWORD_RESET_RATE_LIMIT = "3/minute"  # 3 requests per minute for password reset
