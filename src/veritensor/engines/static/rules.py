# Copyright 2025 Veritensor Security
# Data adapted from ModelScan (Apache 2.0 License)

import re
import logging
import yaml
from pathlib import Path
from typing import Dict, List, Union, Optional, Any

logger = logging.getLogger(__name__)

# Wildcard to indicate the entire module is unsafe
ALL_FUNCTIONS = "*"

# --- Default Signatures (Fallback) ---
DEFAULT_UNSAFE_GLOBALS = {
    "CRITICAL": {
        "__builtin__": ["eval", "compile", "getattr", "apply", "exec", "open", "breakpoint", "__import__"],
        "builtins": ["eval", "compile", "getattr", "apply", "exec", "open", "breakpoint", "__import__"],
        "runpy": ALL_FUNCTIONS,
        "os": ALL_FUNCTIONS,
        "nt": ALL_FUNCTIONS,
        "posix": ALL_FUNCTIONS,
        "socket": ALL_FUNCTIONS,
        "subprocess": ALL_FUNCTIONS,
        "sys": ALL_FUNCTIONS,
        "operator": ["attrgetter"],
        "pty": ALL_FUNCTIONS,
        "pickle": ALL_FUNCTIONS,
        "_pickle": ALL_FUNCTIONS,
        "bdb": ALL_FUNCTIONS,
        "pdb": ALL_FUNCTIONS,
        "shutil": ALL_FUNCTIONS,
        "asyncio": ALL_FUNCTIONS,
        "marshal": ALL_FUNCTIONS,
    },
    "HIGH": {
        "webbrowser": ALL_FUNCTIONS,
        "httplib": ALL_FUNCTIONS,
        "requests.api": ALL_FUNCTIONS,
        "aiohttp.client": ALL_FUNCTIONS,
        "urllib": ALL_FUNCTIONS,
        "urllib2": ALL_FUNCTIONS,
    },
    "MEDIUM": {},
    "LOW": {},
}

DEFAULT_SUSPICIOUS_STRINGS = [
    "/etc/passwd", 
    "AWS_ACCESS_KEY_ID", 
    "OPENAI_API_KEY",
    "curl",
    "wget"
]

DEFAULT_RESTRICTED_LICENSES = [
    "cc-by-nc",
    "agpl",
    "non-commercial",
    "research-only",
]

DEFAULT_PROMPT_INJECTIONS = [
    "Ignore previous instructions",
    "System override",
    "You are now in developer mode"
]

class SignatureLoader:
    """
    Loads security signatures. 
    Priority order:
    1. User Updates (~/.veritensor/signatures.yaml) - Downloaded via 'veritensor update'
    2. Package Defaults (src/.../signatures.yaml) - Bundled with the app
    3. Hardcoded Fallback - If files are missing
    """
    _instance = None
    _globals = DEFAULT_UNSAFE_GLOBALS
    _suspicious = DEFAULT_SUSPICIOUS_STRINGS
    _injections = DEFAULT_PROMPT_INJECTIONS
    
    @classmethod
    def get_globals(cls) -> Dict[str, Dict[str, Any]]:
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._load()
        return cls._instance._globals

    @classmethod
    def get_suspicious_strings(cls) -> List[str]:
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._load()
        return cls._instance._suspicious
    
    @classmethod
    def get_prompt_injections(cls) -> List[str]:
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._load()
        return cls._instance._injections

    
    def _load(self):
        # 1. Check User Home Directory (Updates)
        user_path = Path.home() / ".veritensor" / "signatures.yaml"
        # 2. Check Package Directory (Bundled)
        package_path = Path(__file__).parent / "signatures.yaml"
        
        paths_to_try = [user_path, package_path]
        
        for path in paths_to_try:
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if data:
                            # Update globals if present
                            if "unsafe_globals" in data:
                                self._globals = data["unsafe_globals"]
                            
                            # Update suspicious strings if present
                            if "suspicious_strings" in data:
                                self._suspicious = data["suspicious_strings"]
                            
                            # Update prompt injections if present
                            if "prompt_injections" in data:
                                self._injections = data["prompt_injections"]
                            
                            logger.debug(f"Loaded signatures from {path}")
                            
                            # If we found user updates (first priority), stop looking
                            if path == user_path:
                                logger.debug("Using updated signatures from user directory.")
                                return
                except Exception as e:
                    logger.warning(f"Failed to load signatures from {path}: {e}")

# --- Severity Logic ---

def get_severity(module: str, name: str) -> Optional[str]:
    """
    Checks a module.function pair against the blocklist.
    Returns the severity level (CRITICAL, HIGH, etc.) or None.
    """
    unsafe_globals = SignatureLoader.get_globals()

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        rules = unsafe_globals.get(severity, {})
        
        if module in rules:
            allowed_list = rules[module]
            
            # If the rule is "*", the whole module is blacklisted
            if allowed_list == ALL_FUNCTIONS:
                return severity
            
            # Otherwise, check specific function names
            if isinstance(allowed_list, list) and name in allowed_list:
                return severity

    return None


def is_critical_threat(module: str, name: str) -> bool:
    """Helper to quickly check if an import represents an RCE risk."""
    return get_severity(module, name) == "CRITICAL"

# --- Regex & Matching Logic ---

def is_match(value: str, patterns: List[str]) -> bool:
    """
    Hybrid matcher for strings (Licenses, Model Names, Injections).
    
    Logic:
    1. If rule starts with 'regex:' or 'pattern:' -> treat as Regular Expression.
    2. Otherwise -> treat as simple substring match (case-insensitive).
    """
    if not value:
        return False
        
    for pattern in patterns:
        # --- Mode 1: Regex ---
        if pattern.startswith("regex:") or pattern.startswith("pattern:"):
            # Strip prefix (e.g. "regex:^meta-.*")
            regex_str = pattern.split(":", 1)[1]
            try:
                if re.search(regex_str, value, re.IGNORECASE):
                    return True
            except re.error:
                # Log error but don't crash scan
                logger.warning(f"Invalid regex pattern in config/signatures: {regex_str}")
                continue
        
        # --- Mode 2: Simple Substring (Default) ---
        else:
            if pattern.lower() in value.lower():
                return True
            
    return False

def is_license_restricted(license_str: str, custom_list: List[str] = None) -> bool:
    """Checks if a license string matches restricted rules."""
    patterns = custom_list if custom_list else DEFAULT_RESTRICTED_LICENSES
    return is_match(license_str, patterns)
