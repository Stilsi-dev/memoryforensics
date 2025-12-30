FROM python:3.13-slim

WORKDIR /app

# Install system deps for Volatility/YARA
RUN apt-get update && apt-get install -y \
    build-essential \
    libfuzzy-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project
COPY . .

# Install Python deps
RUN pip install --no-cache-dir \
    fastapi uvicorn python-multipart \
    celery redis \
    pytest pytest-asyncio httpx \
    pyyaml volatility3 yara-python

# Expose ports
EXPOSE 8000 6379 5555

# Default: run API
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
