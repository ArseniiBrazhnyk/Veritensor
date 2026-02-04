# Copyright 2025 Veritensor Security
# Logic adapted from AIsbom (Apache 2.0 License)

import io
import requests
import logging
import boto3
from urllib.parse import urlparse
from typing import Optional, List, Any
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import NoCredentialsError, ClientError

logger = logging.getLogger(__name__)

ALLOWED_DOMAINS = {"huggingface.co", "cdn-lfs.huggingface.co"}

class RemoteStream(io.IOBase):
    """
    A file-like object that reads data from a URL using HTTP Range headers.
    """
    def __init__(self, url: str, session: Optional[requests.Session] = None):
        self._validate_url(url)  
        self.url = url
        self.session = session or requests.Session()
        self.pos = 0
        self.size = self._fetch_size()
        self._closed = False

    def _validate_url(self, url: str):
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(f"Invalid scheme: {parsed.scheme}")
            
            domain = parsed.netloc.lower()
            is_allowed = (domain in ALLOWED_DOMAINS) or (domain.endswith(".huggingface.co"))
            
            if not is_allowed:
                logger.warning(f"Security Warning: Accessing external domain: {domain}")
                
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}")

    def _fetch_size(self) -> int:
        try:
            headers = {"Range": "bytes=0-0"}
            resp = self.session.get(self.url, headers=headers, stream=True, timeout=10)
            resp.raise_for_status()
            
            content_range = resp.headers.get("Content-Range")
            if content_range and "/" in content_range:
                return int(content_range.split("/")[-1])
            
            if "Content-Length" in resp.headers:
                return int(resp.headers["Content-Length"])
            
            return 0
        except Exception as e:
            logger.error(f"Failed to fetch size for {self.url}: {e}")
            raise

    def read(self, size: int = -1) -> bytes:
        if self._closed: raise ValueError("I/O operation on closed file.")
        if self.pos >= self.size: return b""

        if size is None or size < 0:
            end = self.size - 1
        else:
            end = min(self.pos + size - 1, self.size - 1)

        if end < self.pos: return b""

        headers = {"Range": f"bytes={self.pos}-{end}"}
        try:
            resp = self.session.get(self.url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.content
            self.pos += len(data)
            return data
        except Exception as e:
            logger.error(f"Read error at offset {self.pos}: {e}")
            raise

    def seek(self, offset: int, whence: int = 0) -> int:
        if self._closed: raise ValueError("I/O operation on closed file.")
        if whence == 0: new_pos = offset
        elif whence == 1: new_pos = self.pos + offset
        elif whence == 2: new_pos = self.size + offset
        else: raise ValueError(f"Invalid whence value: {whence}")
        self.pos = max(0, min(new_pos, self.size))
        return self.pos

    def tell(self) -> int: return self.pos
    def seekable(self) -> bool: return True
    def readable(self) -> bool: return True
    def close(self): self._closed = True
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): self.close()


class S3Stream(io.IOBase):
    """
    A file-like object that reads data from S3 using Range requests.
    Supports both Authenticated (Env vars) and Anonymous (Public buckets) access.
    """
    def __init__(self, s3_url: str):
        parsed = urlparse(s3_url)
        self.bucket = parsed.netloc
        self.key = parsed.path.lstrip("/")
        self.pos = 0
        self._closed = False

        # 1. Try standard client (Env vars / ~/.aws/credentials / IAM Role)
        self.s3 = boto3.client("s3")
        
        try:
            self.size = self._fetch_size()
        except (NoCredentialsError, ClientError) as e:
            # Check if it is a 404 (Not Found) - no point trying anonymous
            error_code = e.response['Error']['Code'] if hasattr(e, 'response') else ""
            if "404" in str(error_code):
                logger.error(f"S3 Object not found: {s3_url}")
                raise

            # 2. Fallback: Try anonymous access (for public buckets)
            logger.info(f"AWS Creds failed ({error_code}). Trying anonymous access for {s3_url}...")
            self.s3 = boto3.client("s3", config=Config(signature_version=UNSIGNED))
            self.size = self._fetch_size()

    def _fetch_size(self) -> int:
        try:
            resp = self.s3.head_object(Bucket=self.bucket, Key=self.key)
            return resp["ContentLength"]
        except Exception as e:
            # We catch this in __init__ to handle fallback, but if it fails again, we log
            logger.debug(f"Failed to access S3 object {self.bucket}/{self.key}: {e}")
            raise

    def read(self, size: int = -1) -> bytes:
        if self._closed: raise ValueError("I/O operation on closed file.")
        if self.pos >= self.size: return b""

        if size is None or size < 0:
            end = self.size - 1
        else:
            end = min(self.pos + size - 1, self.size - 1)

        if end < self.pos: return b""

        # S3 Range is inclusive (e.g. "bytes=0-9")
        range_header = f"bytes={self.pos}-{end}"
        try:
            resp = self.s3.get_object(Bucket=self.bucket, Key=self.key, Range=range_header)
            data = resp["Body"].read()
            self.pos += len(data)
            return data
        except Exception as e:
            logger.error(f"S3 Read error: {e}")
            raise

    def seek(self, offset: int, whence: int = 0) -> int:
        if self._closed: raise ValueError("I/O operation on closed file.")
        if whence == 0: new_pos = offset
        elif whence == 1: new_pos = self.pos + offset
        elif whence == 2: new_pos = self.size + offset
        else: raise ValueError(f"Invalid whence value: {whence}")
        self.pos = max(0, min(new_pos, self.size))
        return self.pos

    def tell(self) -> int: return self.pos
    def seekable(self) -> bool: return True
    def readable(self) -> bool: return True
    def close(self): self._closed = True
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): self.close()

def get_stream_for_path(path: str):
    """Factory to get correct stream (S3 or HTTP)."""
    if path.startswith("s3://"):
        return S3Stream(path)
    elif path.startswith("http://") or path.startswith("https://"):
        return RemoteStream(path)
    else:
        # Local file
        return open(path, "rb")

def resolve_huggingface_repo(repo_id: str) -> List[str]:
    """
    Queries the Hugging Face API to get direct file URLs for a repository.
    Handles 'hf://' prefix.
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
    supported_exts = (".pt", ".pth", ".bin", ".safetensors", ".gguf", ".pkl")
    urls = []
    for entry in files_info:
        path = entry.get("path", "")
        if any(path.endswith(ext) for ext in supported_exts):
            urls.append(f"https://huggingface.co/{repo_id}/resolve/main/{path}")
    return urls
