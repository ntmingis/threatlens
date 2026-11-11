# NOT built or tested in v0.1 development (no Docker in the build sandbox). Review before relying on it.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends clamav && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /app scanner
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn[standard]>=0.30" "python-multipart>=0.0.9" "pymupdf>=1.24" "httpx>=0.27"
COPY backend ./backend
COPY frontend ./frontend
COPY config ./config
ENV PYTHONPATH=/app/backend THREATLENS_DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1
USER scanner
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "threatlens.main:app", "--host", "0.0.0.0", "--port", "8000"]
