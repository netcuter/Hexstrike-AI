FROM python:3.11-slim

WORKDIR /app

# Install system security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    gobuster \
    dirb \
    hydra \
    sqlmap \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install ML dependencies
COPY requirements-ml.txt .
RUN pip install --no-cache-dir -r requirements-ml.txt || true

# Copy application
COPY . .

# Expose API port
EXPOSE 8888

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8888/health || exit 1

# Default: run the API server
CMD ["python3", "hexstrike_server.py", "--port", "8888"]
