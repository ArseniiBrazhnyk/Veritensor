# Copyright 2025 Veritensor Security
#
# This module integrates with Sigstore Cosign.
# It wraps the 'cosign' CLI binary using subprocess to sign OCI artifacts.
#
# Why subprocess?
# The official Sigstore Python SDK is often behind the Go CLI in features.
# Calling the binary is the industry standard for CI/CD integrations.

import shutil
import logging
import subprocess
import os
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Default timeout for signing operations (seconds)
SIGNING_TIMEOUT = 60


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

    Args:
        image_ref: The image tag (e.g., 'myrepo/model:v1').
        key_path: Path to the 'cosign.key' private key file.
        annotations: Metadata to attach (e.g., {'scanned_by': 'veritensor', 'status': 'clean'}).
        tlog_upload: Whether to upload to the public Rekor transparency log. 
                     Defaults to False for enterprise privacy.

    Returns:
        True if signing succeeded, False otherwise.
    """
    if not is_cosign_available():
        logger.error("Cosign binary not found. Please install it or use the Veritensor Docker image.")
        return False

    if not Path(key_path).exists():
        # Check if it's maybe a raw key content in an env var (advanced case),
        # but for MVP we expect a file.
        logger.error(f"Private key file not found at: {key_path}")
        return False

    # Build the command
    # cosign sign --key <key> --tlog-upload=false -a key=val image:tag -y
    cmd = [
        "cosign", "sign",
        "--key", key_path,
        "-y"  # Skip confirmation prompts
    ]

    # Handle Transparency Log (Rekor)
    # For private enterprise models, we usually disable this to avoid leaking metadata.
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
        
        # We pass os.environ to allow COSIGN_PASSWORD to be picked up if set
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SIGNING_TIMEOUT,
            env=os.environ
        )

        if result.returncode == 0:
            logger.info(f"Successfully signed {image_ref}")
            logger.debug(f"Cosign output: {result.stdout}")
            return True
        else:
            logger.error(f"Cosign signing failed (Code {result.returncode})")
            logger.error(f"Stderr: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"Signing timed out after {SIGNING_TIMEOUT} seconds.")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during signing: {e}")
        return False


def generate_key_pair(output_prefix: str = "veritensor") -> bool:
    """
    Generates a new key pair (veritensor.key and veritensor.pub).
    Useful for the 'veritensor keygen' CLI command.
    """
    if not is_cosign_available():
        logger.error("Cosign binary not found.")
        return False

    cmd = ["cosign", "generate-key-pair"]
    
    # Cosign asks for a password interactively. 
    # For automation, we can set COSIGN_PASSWORD env var, 
    # but 'veritensor keygen' is usually run interactively by a human.
    
    try:
        # We don't capture output here to let the user interact with the password prompt
        subprocess.run(cmd, check=True)
        
        # Rename default 'cosign.key'/'cosign.pub' if needed, 
        # but cosign generates them with these names by default.
        if output_prefix != "cosign":
            if Path("cosign.key").exists():
                shutil.move("cosign.key", f"{output_prefix}.key")
            if Path("cosign.pub").exists():
                shutil.move("cosign.pub", f"{output_prefix}.pub")
                
        return True
    except subprocess.CalledProcessError:
        logger.error("Failed to generate key pair.")
        return False
