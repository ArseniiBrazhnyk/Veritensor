# Copyright 2025 Aegis Security
#
# This module integrates with Sigstore Cosign to sign OCI artifacts (Docker images).
# It requires the 'cosign' binary to be installed in the system PATH.

import os
import shutil
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class CosignError(Exception):
    """Custom exception for signing failures."""
    pass


def is_cosign_installed() -> bool:
    """Checks if the cosign binary is available in PATH."""
    return shutil.which("cosign") is not None


def sign_container(
    image_ref: str,
    key_path: Optional[str] = None,
    key_content: Optional[str] = None,
    annotations: Optional[Dict[str, str]] = None,
    tlog_upload: bool = False
) -> None:
    """
    Signs a container image using a private key.

    Args:
        image_ref: The image tag to sign (e.g., "myrepo/model:v1").
        key_path: Path to the cosign.key file.
        key_content: Raw content of the private key (if stored in ENV).
        annotations: Key-value pairs to attach to the signature (e.g., status=clean).
        tlog_upload: Whether to upload to the public Transparency Log (Rekor).
                     Defaults to False for private enterprise artifacts.

    Raises:
        CosignError: If signing fails.
    """
    if not is_cosign_installed():
        raise CosignError("Cosign binary not found. Please install it or use the Aegis Docker image.")

    # We need a file path for the key. If provided via ENV/String, write to temp.
    temp_key_file = None
    final_key_path = key_path

    try:
        # 1. Handle Key Source
        if not final_key_path and key_content:
            # Create a secure temporary file
            temp_key_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
            temp_key_file.write(key_content)
            temp_key_file.close() # Close so subprocess can read it
            final_key_path = temp_key_file.name
            logger.debug(f"Created temporary key file at {final_key_path}")

        if not final_key_path:
            raise CosignError("No private key provided (path or content).")

        # 2. Construct Command
        # cosign sign --key <key> --tlog-upload=<bool> <image> -a key=val
        cmd = [
            "cosign", "sign",
            "--key", final_key_path,
            f"--tlog-upload={'true' if tlog_upload else 'false'}",
            "--yes", # Skip confirmation prompts
            image_ref
        ]

        # Add Annotations
        if annotations:
            for k, v in annotations.items():
                cmd.extend(["-a", f"{k}={v}"])

        # 3. Execute
        logger.info(f"Signing artifact: {image_ref}")
        logger.debug(f"Command: {' '.join(cmd)}")

        # Pass current environment (needed for COSIGN_PASSWORD if key is encrypted)
        env = os.environ.copy()

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env
        )

        if result.returncode != 0:
            # Redact key path from error logs for safety
            err_msg = result.stderr.replace(final_key_path, "[KEY_PATH]")
            raise CosignError(f"Cosign failed (Exit {result.returncode}): {err_msg}")

        logger.info("Successfully signed container.")
        logger.debug(f"Cosign Output: {result.stdout}")

    except OSError as e:
        raise CosignError(f"System error during signing: {e}")
    
    finally:
        # 4. Cleanup Temporary Key
        if temp_key_file:
            try:
                os.unlink(temp_key_file.name)
                logger.debug("Cleaned up temporary key file.")
            except OSError:
                logger.warning("Failed to delete temporary key file.")


def generate_key_pair(output_dir: str = ".") -> None:
    """
    Helper to generate a new key pair (for 'aegis keygen').
    """
    if not is_cosign_installed():
        raise CosignError("Cosign binary not found.")

    try:
        # cosign generate-key-pair
        # Note: This might prompt for a password interactively.
        subprocess.run(["cosign", "generate-key-pair"], cwd=output_dir, check=True)
    except subprocess.CalledProcessError as e:
        raise CosignError(f"Failed to generate keys: {e}")
