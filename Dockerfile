# Project Mathra - Production Multi-Stage Dockerfile
FROM python:3.12-slim AS base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Security Checkpoint: Create unprivileged user (CWE-250 Mitigation)
RUN useradd -m -u 10001 appuser && \
    mkdir -p /app/backend/data /app/redteam/reports && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000 8501

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command launches the FastAPI Gateway
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
