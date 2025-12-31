# Copyright 2025 Aegis Security
# Adapted from huggingface_hub (Apache 2.0 License)
#
# This module implements hashing logic identical to Hugging Face Hub.
# It handles standard files and Git LFS pointers transparently.

import hashlib
import logging
from pathlib import Path
from typing import BinaryIO, Union, Optional

# Import LFS parser from the sibling module
from .lfs import parse_lfs_pointer

logger = logging.getLogger(__name__)

# Default chunk size used by Hugging Face (1MB).
DEFAULT_CHUNK_SIZE = 1024 * 1024


def calculate_sha256(
    file_input: Union[str, Path, BinaryIO], 
    chunk_size: Optional[int] = None
) -> str:
    """
    Computes the SHA256 hash of a file.
    
    If the file is a Git LFS pointer, returns the hash referenced inside the pointer.
    Otherwise, computes the hash of the file content.

    Args:
        file_input: Path to the file or a file-like object (opened in 'rb' mode).
        chunk_size: Size of chunks to read. Defaults to 1MB.

    Returns:
        The hexadecimal SHA256 string.
    """
    chunk_size = chunk_size or DEFAULT_CHUNK_SIZE

    if isinstance(file_input, (str, Path)):
        with open(file_input, "rb") as f:
            return _compute_sha256_from_stream(f, chunk_size)
    else:
        # Assume it is a file-like object
        return _compute_sha256_from_stream(file_input, chunk_size)


def _compute_sha256_from_stream(fileobj: BinaryIO, chunk_size: int) -> str:
    """
    Internal helper to compute SHA256 from a stream.
    Includes LFS pointer detection.
    """
    # 1. Try to detect LFS pointer first
    start_pos = 0
    try:
        start_pos = fileobj.tell()
        # Read enough bytes to check for LFS header (usually < 200 bytes)
        header_sample = fileobj.read(1024)
        
        # Check if it's an LFS pointer
        lfs_info = parse_lfs_pointer(header_sample)
        if lfs_info:
            logger.debug("Detected LFS pointer, using OID from metadata.")
            return lfs_info["sha256"]
            
        # If not LFS, reset cursor to start to read the whole file
        fileobj.seek(start_pos)
        
    except (OSError, AttributeError):
        # If stream is not seekable (e.g. pipe), we can't check LFS reliably 
        # without consuming data. We proceed to standard hashing.
        logger.debug("Stream not seekable, skipping LFS check.")
        pass

    # 2. Standard SHA256 calculation
    sha = hashlib.sha256()
    
    while True:
        chunk = fileobj.read(chunk_size)
        if not chunk:
            break
        sha.update(chunk)
    
    # Try to reset cursor to start, so the file can be read again if needed by other engines
    try:
        fileobj.seek(start_pos)
    except (OSError, AttributeError):
        pass

    return sha.hexdigest()


def calculate_git_hash(data: bytes) -> str:
    """
    Computes the Git-SHA1 hash of bytes (Blob format).
    
    This is equivalent to running `git hash-object`.
    Used primarily for verifying small files (like config.json) or 
    LFS pointer files themselves.

    Logic: sha1("blob " + filesize + "\0" + data)

    Args:
        data: The raw bytes of the file.

    Returns:
        The hexadecimal Git-SHA1 string.
    """
    # Logic taken from huggingface_hub/utils/sha.py
    sha = hashlib.sha1()
    sha.update(b"blob ")
    sha.update(str(len(data)).encode("utf-8"))
    sha.update(b"\0")
    sha.update(data)
    return sha.hexdigest()
