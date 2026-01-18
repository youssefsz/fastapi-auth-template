# ============================================
# FastAPI Auth Template - Dockerfile
# Uses uv for fast Python dependency management
# ============================================

# Build stage with uv
FROM python:3.12-slim AS builder

# Install uv 
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set working directory
WORKDIR /app

# Copy dependency files first for better layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies using uv (creates .venv in /app)
RUN uv sync --frozen --no-dev --no-install-project

# Copy source files
COPY . .

# ============================================
# Production stage - minimal runtime image
# ============================================
FROM python:3.12-slim AS production

# Create non-root user for security
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid 1000 --shell /bin/bash appuser

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app /app

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose the port (default FastAPI port)
EXPOSE 8000

# Health check endpoint
HEALTHCHECK --interval=5s --timeout=5s --retries=5 --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

# Start the server with uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
