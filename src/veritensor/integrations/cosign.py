# Copyright 2025 Veritensor Security
#
# This module integrates with Sigstore Cosign.
# It wraps the 'cosign' CLI binary using subprocess to sign OCI artifacts.
#
# The official Sigstore Python SDK is often behind the Go CLI in features.
# Calling the binary is the industry standard for CI/CD integrations.

import shutil
import logging
import subprocess
import os
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

def is_cosign_available() -> bool:
    """Checks if the 'cosign' binary is in the system PATH."""
    return shutil.which("cosign") is not None


def sign_container(
    image_ref: str,
    key_path: str,
    annotations: Optional[Dict[str, str]] = None,
    tlog_upload: bool = False
) -> bool:
    """
    Signs a container image using a private key.
    """
    if not is_cosign_available():
        logger.error("Cosign binary not found. Please install it or use the Veritensor Docker image.")
        return False

    if not Path(key_path).exists():
        logger.error(f"Private key file not found at: {key_path}")
        return False

    # Build the command
    cmd = [
        "cosign", "sign",
        "--key", key_path,
        "-y"  # Skip confirmation prompts
    ]


    # Handle Transparency Log (Rekor)
    # We disable this by default to prevent leaking enterprise metadata to public logs.
    if not tlog_upload:
        cmd.append("--tlog-upload=false")

    # Add Annotations
    if annotations:
        for key, value in annotations.items():
            cmd.extend(["-a", f"{key}={value}"])

    # Target Image
    cmd.append(image_ref)

    try:
        logger.info(f"Signing image {image_ref} with key {key_path}...")
        
        # We allow direct interaction (stdin/stdout) so the user can type the password.
        # Note: In CI/CD, use COSIGN_PASSWORD env var to avoid prompts.
        result = subprocess.run(
            cmd,
            capture_output=False, # Allow user to see prompts
            text=True,
            env=os.environ
        )

        if result.returncode == 0:
            logger.info(f"Successfully signed {image_ref}")
            return True
        else:
            logger.error(f"Cosign signing failed (Code {result.returncode})")
            return False

    except KeyboardInterrupt:
        logger.error("Signing cancelled by user.")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during signing: {e}")
        return False


def generate_key_pair(output_prefix: str = "veritensor") -> bool:
    """
    Generates a new key pair.
    """
    if not is_cosign_available():
        logger.error("Cosign binary not found.")
        return False

    cmd = ["cosign", "generate-key-pair"]
    
    try:
        # Interactive generation
        subprocess.run(cmd, check=True)
        
        if output_prefix != "cosign":
            if Path("cosign.key").exists():
                shutil.move("cosign.key", f"{output_prefix}.key")
            if Path("cosign.pub").exists():
                shutil.move("cosign.pub", f"{output_prefix}.pub")
                
        return True
    except subprocess.CalledProcessError:
        logger.error("Failed to generate key pair.")
        return False
