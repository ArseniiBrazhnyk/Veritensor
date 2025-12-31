# Stage 1: Base Image
FROM python:3.11-slim-bookworm

# Install system dependencies
# curl: required to download Cosign
# git: required if we add git-based checks later
RUN apt-get update && apt-get install -y curl git && rm -rf /var/lib/apt/lists/*

# --- Install Cosign (Sigstore) ---
# We download the official binary to ensure we have the latest signing capabilities.
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/sigstore/cosign/releases/latest | grep tag_name | cut -d '"' -f 4) && \
    curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" && \
    mv cosign-linux-amd64 /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# --- Install Veritensor ---
WORKDIR /app

# Copy dependency definition first to leverage Docker layer caching
COPY pyproject.toml .

# Create a dummy package structure to allow installing dependencies
# before the actual code is copied. This speeds up re-builds.
RUN mkdir -p src/veritensor && touch src/veritensor/__init__.py
RUN pip install --no-cache-dir .

# Copy the actual source code and configuration
COPY src/ src/
COPY veritensor.yaml .

# Re-install the package to link the actual source code
RUN pip install .

# --- Setup Entrypoint ---
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# The entrypoint script will handle argument parsing
ENTRYPOINT ["/entrypoint.sh"]
