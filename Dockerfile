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

# [FIXED] Copy dependency definition from ROOT (removed 'scanner/')
COPY pyproject.toml .

# Create dummy package structure to allow installing dependencies
# before the actual code is copied. This speeds up re-builds.
RUN mkdir -p src/veritensor && touch src/veritensor/__init__.py
RUN pip install --no-cache-dir .

# [FIXED] Copy source code from ROOT (removed 'scanner/')
COPY src/ src/

# [FIXED] Copy config from ROOT
# ВАЖНО: Убедитесь, что файл veritensor.yaml существует в корне репозитория!
# Если его нет на скриншоте, создайте его, иначе сборка упадет.
COPY veritensor.yaml .

# Re-install the package to link the actual source code
RUN pip install .

# --- Setup Entrypoint ---
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# The entrypoint script will handle argument parsing
ENTRYPOINT ["/entrypoint.sh"]
