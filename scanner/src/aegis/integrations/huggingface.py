# Copyright 2025 Veritensor Security
#
# This module interacts with the Hugging Face Hub API.
# It verifies if a local file's hash matches the official record in the Hub.

import requests
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

HF_API_BASE = "https://huggingface.co/api/models"

class HuggingFaceClient:
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.headers = {}
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    def get_model_info(self, repo_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetches metadata for a model repository.
        """
        url = f"{HF_API_BASE}/{repo_id}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 401:
                logger.warning(f"Access denied to {repo_id}. Check your HF_TOKEN.")
            elif resp.status_code == 404:
                logger.warning(f"Model {repo_id} not found on Hugging Face.")
            else:
                logger.warning(f"HF API Error: {resp.status_code}")
        except Exception as e:
            logger.error(f"Network error connecting to HF: {e}")
        
        return None

    def verify_file_hash(self, repo_id: str, filename: str, local_sha256: str) -> str:
        """
        Verifies if the local file hash matches the remote file in the repo.
        
        Returns:
            "VERIFIED": Hash matches exactly.
            "MISMATCH": File exists but hash is different (Tampering risk).
            "UNKNOWN": File not found in repo or repo inaccessible.
        """
        model_info = self.get_model_info(repo_id)
        if not model_info:
            return "UNKNOWN"

        # The API returns a list of 'siblings' (files)
        siblings = model_info.get("siblings", [])
        
        remote_file_info = None
        for file_obj in siblings:
            if file_obj.get("rfilename") == filename:
                remote_file_info = file_obj
                break
        
        if not remote_file_info:
            # Collecting a list of available files for a hint
            available_files = [f.get("rfilename") for f in siblings]
            
            # We form a string (the first 5 files)
            preview = ", ".join(available_files[:5])
            if len(available_files) > 5:
                preview += "..."

            logger.warning(f"File '{filename}' not found in remote repo '{repo_id}'.")
            logger.warning(f"Available files in repo: [{preview}]")
            return "UNKNOWN"
        remote_hash = None 
        # Case 1: LFS Object
        if "lfs" in remote_file_info:
            remote_hash = remote_file_info["lfs"].get("oid") 
        
        # Case 2: Regular file (sometimes sha256 is not explicitly listed in basic call)
        # In a robust implementation, we would call /api/models/{repo_id}/paths-info/main
        # Let's implement a fallback to paths-info for better accuracy.
        
        if not remote_hash:
            return self._verify_via_paths_info(repo_id, filename, local_sha256)

        if remote_hash == local_sha256:
            return "VERIFIED"
        else:
            logger.warning(f"Hash Mismatch for {filename}! Local: {local_sha256}, Remote: {remote_hash}")
            return "MISMATCH"

    def _verify_via_paths_info(self, repo_id: str, filename: str, local_sha256: str) -> str:
        """
        Fallback method using the paths-info endpoint which provides detailed LFS info.
        """
        url = f"{HF_API_BASE}/{repo_id}/paths-info/main"
        try:
            resp = requests.post(url, headers=self.headers, json={"paths": [filename]}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 0:
                    # data is list of dicts.
                    info = data[0]
                    # Check LFS
                    if "lfs" in info and info["lfs"]:
                        remote_hash = info["lfs"]["oid"]
                        if remote_hash == local_sha256:
                            return "VERIFIED"
                        else:
                            return "MISMATCH"
        except Exception:
            pass
            
        return "UNKNOWN"
