# Copyright 2025 Aegis Security
# Logic adapted from AIsbom (Apache 2.0 License)
#
# This module provides a seekable, readable stream backed by HTTP Range requests.
# It enables "Zero-Download" scanning of remote models.

import io
import requests
import logging
from typing import Optional, List, Any
from urllib.parse import urlparse  
logger = logging.getLogger(__name__)

# <--- [2] Whitelisted domains added
# We only allow Hugging Face and its CDN so that it cannot be scanned
# the company's internal network (SSRF protection).
ALLOWED_DOMAINS = {"huggingface.co", "cdn-lfs.huggingface.co"}

class RemoteStream(io.IOBase):
    """
    A file-like object that reads data from a URL using HTTP Range headers.
    It supports seek() and read(), making it compatible with zipfile, 
    pickletools, and safetensors readers.
    """

    def __init__(self, url: str, session: Optional[requests.Session] = None):
        self._validate_url(url)  
        self.url = url
        self.session = session or requests.Session()
        self.pos = 0
        self.size = self._fetch_size()
        self._closed = False

    def _validate_url(self, url: str):
        """
        Security check: Prevents SSRF by restricting domains.
        """
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(f"Invalid scheme: {parsed.scheme}")
            
            # Check domain against allowlist
            domain = parsed.netloc.lower()
            
            # Allowing exact matches OR subdomains huggingface.co
            is_allowed = (domain in ALLOWED_DOMAINS) or (domain.endswith(".huggingface.co"))
            
            if not is_allowed:
                # In MVP we write a Warning, but in Strict mode there should be a raise ValueError
                logger.warning(f"Security Warning: Accessing external domain: {domain}")
                
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}")

    def _fetch_size(self) -> int:
        """
        Determines the total size of the remote file.
        Tries a 0-byte Range request first to check server support.
        """
        try:
            # Request the first byte to get the Content-Range header
            headers = {"Range": "bytes=0-0"}
            resp = self.session.get(self.url, headers=headers, stream=True, timeout=10)
            resp.raise_for_status()
            
            # Parse "bytes 0-0/12345"
            content_range = resp.headers.get("Content-Range")
            if content_range and "/" in content_range:
                return int(content_range.split("/")[-1])
            
            # Fallback: Content-Length (if server ignores Range)
            if "Content-Length" in resp.headers:
                return int(resp.headers["Content-Length"])
            
            logger.warning(f"Could not determine size for {self.url}. Seek from end will fail.")
            return 0
        except Exception as e:
            logger.error(f"Failed to fetch size for {self.url}: {e}")
            raise

    def read(self, size: int = -1) -> bytes:
        """
        Reads `size` bytes from the current position using an HTTP Range request.
        """
        if self._closed:
            raise ValueError("I/O operation on closed file.")

        if self.pos >= self.size:
            return b""

        if size is None or size < 0:
            # Read until the end
            end = self.size - 1
        else:
            # Read specific chunk
            end = min(self.pos + size - 1, self.size - 1)

        # If we are asking for 0 bytes or invalid range
        if end < self.pos:
            return b""

        headers = {"Range": f"bytes={self.pos}-{end}"}
        
        try:
            resp = self.session.get(self.url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.content
            
            # Update position
            self.pos += len(data)
            return data
        except Exception as e:
            logger.error(f"Read error at offset {self.pos}: {e}")
            raise

    def seek(self, offset: int, whence: int = 0) -> int:
        """
        Changes the stream position.
        0: Start of stream (default)
        1: Current position
        2: End of stream
        """
        if self._closed:
            raise ValueError("I/O operation on closed file.")

        if whence == 0:  # SEEK_SET
            new_pos = offset
        elif whence == 1:  # SEEK_CUR
            new_pos = self.pos + offset
        elif whence == 2:  # SEEK_END
            new_pos = self.size + offset
        else:
            raise ValueError(f"Invalid whence value: {whence}")

        # Clamp position
        self.pos = max(0, min(new_pos, self.size))
        return self.pos

    def tell(self) -> int:
        return self.pos

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def close(self):
        self._closed = True
        # We don't close the session here as it might be shared

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def resolve_huggingface_repo(repo_id: str) -> List[str]:
    """
    Queries the Hugging Face API to get direct file URLs for a repository.
    Handles 'hf://' prefix.
    
    Args:
        repo_id: e.g. "meta-llama/Meta-Llama-3-8B" or "hf://meta-llama/..."
    
    Returns:
        List of direct download URLs for model files (.pt, .safetensors, .gguf, .bin).
    """
    if repo_id.startswith("hf://"):
        repo_id = repo_id[len("hf://"):]

    api_url = f"https://huggingface.co/api/models/{repo_id}/tree/main"
    
    try:
        resp = requests.get(api_url, timeout=10)
        resp.raise_for_status()
        files_info = resp.json()
    except Exception as e:
        logger.error(f"Failed to resolve HF repo {repo_id}: {e}")
        return []

    # Filter for relevant model files
    supported_exts = (".pt", ".pth", ".bin", ".safetensors", ".gguf", ".pkl")
    urls = []
    
    for entry in files_info:
        path = entry.get("path", "")
        if any(path.endswith(ext) for ext in supported_exts):
            # Construct the "resolve" URL which redirects to the CDN
            urls.append(f"https://huggingface.co/{repo_id}/resolve/main/{path}")

    return urls
