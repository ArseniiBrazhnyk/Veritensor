# Copyright 2025 Aegis Security
# Logic adapted from huggingface_hub (Apache 2.0 License)
#
# This module handles Git LFS (Large File Storage) pointers.
# It ensures we don't mistakenly hash a pointer file as if it were the model itself.

from typing import Optional, Tuple, Dict

# The standard prefix for LFS pointer files
LFS_HEADER = b"version https://git-lfs.github.com/spec/v1"


def parse_lfs_pointer(data: bytes) -> Optional[Dict[str, str]]:
    """
    Checks if the byte data is a Git LFS pointer.
    
    If it is, returns a dictionary with 'oid' (sha256) and 'size'.
    If not, returns None.
    
    Args:
        data: The raw bytes of the file (usually the first 1KB is enough).
    
    Returns:
        dict: {'oid': '...', 'size': '...'} or None
    """
    if not data.startswith(LFS_HEADER):
        return None

    try:
        # LFS pointers are text files, usually very small (< 200 bytes)
        text = data.decode("utf-8", errors="ignore")
        lines = text.strip().split("\n")
        
        info = {}
        for line in lines:
            parts = line.split(" ", 1)
            if len(parts) == 2:
                key, value = parts
                info[key] = value.strip()
        
        # Validate that we found the necessary fields
        if "oid" in info and "size" in info:
            # oid format is usually "sha256:hash..."
            oid_parts = info["oid"].split(":")
            if len(oid_parts) == 2 and oid_parts[0] == "sha256":
                return {
                    "sha256": oid_parts[1],
                    "size": int(info["size"])
                }
    except Exception:
        # If parsing fails, it's likely not a valid pointer
        return None

    return None


def is_lfs_pointer(file_path: str) -> bool:
    """
    Helper to check a file on disk without reading the whole thing.
    """
    try:
        with open(file_path, "rb") as f:
            # Read just enough to check the header and parse lines
            head = f.read(1024) 
            return parse_lfs_pointer(head) is not None
    except OSError:
        return False
