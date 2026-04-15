FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for clickhouse-connect
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir .

COPY analyzer/ ./analyzer/

EXPOSE 8080

CMD ["uvicorn", "analyzer.main:app", "--host", "0.0.0.0", "--port", "8080"]
