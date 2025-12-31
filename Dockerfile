# Stage 1: Base Image
FROM python:3.11-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y curl git && rm -rf /var/lib/apt/lists/*

# --- Install Cosign (Sigstore) ---
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/sigstore/cosign/releases/latest | grep tag_name | cut -d '"' -f 4) && \
    curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" && \
    mv cosign-linux-amd64 /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# --- Install Veritensor ---
WORKDIR /app

# [CHANGED] Copy dependency definition from scanner folder
COPY scanner/pyproject.toml .

# Create dummy package structure
RUN mkdir -p src/veritensor && touch src/veritensor/__init__.py
RUN pip install --no-cache-dir .

# [CHANGED] Copy source code from scanner folder
COPY scanner/src/ src/

# [CHANGED] Copy config from root (it is already here)
COPY veritensor.yaml .

# Re-install package
RUN pip install .

# --- Setup Entrypoint ---
# [CHANGED] Copy entrypoint from root (it is already here)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
