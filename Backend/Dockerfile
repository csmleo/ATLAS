# ==============================================================================
# Phishing-EML-Analyzer — Dockerfile
# ==============================================================================
# Multi-stage, security-hardened container image.
# Runs as non-root user. Uses Python 3.11 slim base.
#
# Build:  docker build -t phishing-eml-analyzer .
# Run:    docker run --rm -v $(pwd)/originals:/app/originals \
#                        -v $(pwd)/reportes:/app/reportes \
#                        --env-file .env \
#                        phishing-eml-analyzer -f originals/sample_phishing_bec.eml
# ==============================================================================

FROM python:3.11-slim

LABEL maintainer="alfaggodoy <alfagabri.godoy@gmail.com>"
LABEL description="Phishing-EML-Analyzer — Automated Email Forensic Engine & SOAR Pipeline"
LABEL version="1.0.0"

# --- System dependencies ---
# libmagic1: required by python-magic for MIME type detection
# libssl-dev: required for cryptographic DNS validation
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 \
        libssl-dev \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# --- Create non-root user for security ---
RUN groupadd --gid 1001 analyzer && \
    useradd --uid 1001 --gid analyzer --shell /bin/bash --create-home analyzer

WORKDIR /app

# --- Install Python dependencies ---
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# --- Copy application source ---
COPY src/       ./src/
COPY data/      ./data/
COPY main.py    .

# --- Create writable output directories ---
RUN mkdir -p originals reportes screenshots logs && \
    chown -R analyzer:analyzer /app

# --- Switch to non-root user ---
USER analyzer

# --- Default entrypoint ---
ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
