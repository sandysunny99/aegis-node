FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (curl for healthcheck, gcc for native extensions, libmagic for MIME)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner package — build context is project root so ../scanner is just ./scanner
COPY scanner/ ./scanner/

# Copy backend source (config, models, routers, services, main.py etc.)
COPY backend/ .

# Create runtime data directories
RUN mkdir -p /app/data/samples /app/data/quarantine /app/data/sanitized /app/data/reports

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
