#!/bin/bash
set -e

# Copyright 2025 Veritensor
# Entrypoint script for the Docker container.
# It maps positional arguments from action.yml to veritensor CLI flags.

# 1. Capture arguments from action.yml
INPUT_PATH="$1"
INPUT_REPO="$2"
INPUT_IMAGE="$3"
INPUT_FORCE="$4"
INPUT_FORMAT="$5"

# 2. Build the command dynamically
# We start with the base command
CMD="veritensor scan $INPUT_PATH"

# 3. Append optional flags if they are provided

if [ -n "$INPUT_REPO" ]; then
    echo "::notice::Verifying integrity against Hugging Face repo: $INPUT_REPO"
    CMD="$CMD --repo $INPUT_REPO"
fi

if [ -n "$INPUT_IMAGE" ]; then
    echo "::notice::Container signing enabled for: $INPUT_IMAGE"
    CMD="$CMD --image $INPUT_IMAGE"
fi

if [ "$INPUT_FORCE" = "true" ]; then
    echo "::warning::Break-glass mode enabled. Build will NOT fail on threats."
    CMD="$CMD --force"
fi

if [ "$INPUT_FORMAT" = "json" ]; then
    CMD="$CMD --json"
fi

# 4. Execute the command
# We print the command for debugging purposes (masking sensitive info if needed)
echo "Running: $CMD"
eval "$CMD"
