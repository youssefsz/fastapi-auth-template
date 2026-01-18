"""
FastAPI Authentication System Entry Point.

Run with: uvicorn main:app --reload
Or: python main.py
"""

import uvicorn

from app.main import app
from app.core.config import settings


def main() -> None:
    """Run the FastAPI application."""
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.is_development,
        log_level="debug" if settings.debug else "info",
    )


if __name__ == "__main__":
    main()
