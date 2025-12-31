# Copyright 2025 Aegis Security
# Data adapted from ModelScan (Apache 2.0 License)
#
# This module defines the "Blocklist" of unsafe Python globals.
# It categorizes threats by severity (CRITICAL = RCE, HIGH = Network/Exfiltration).

from typing import Dict, List, Union, Optional

# Wildcard to indicate the entire module is unsafe
ALL_FUNCTIONS = "*"

# --- The Ultimate Blacklist ---
# Source: ModelScan/modelscan/settings.py
UNSAFE_GLOBALS = {
    "CRITICAL": {
        "__builtin__": [
            "eval",
            "compile",
            "getattr",
            "apply",
            "exec",
            "open",
            "breakpoint",
            "__import__",
        ],  # Pickle versions 0, 1, 2 use '__builtin__'
        "builtins": [
            "eval",
            "compile",
            "getattr",
            "apply",
            "exec",
            "open",
            "breakpoint",
            "__import__",
        ],  # Pickle versions 3, 4 use 'builtins'
        "runpy": ALL_FUNCTIONS,
        "os": ALL_FUNCTIONS,
        "nt": ALL_FUNCTIONS,      # Alias for 'os' on Windows
        "posix": ALL_FUNCTIONS,   # Alias for 'os' on Linux
        "socket": ALL_FUNCTIONS,  # Network access
        "subprocess": ALL_FUNCTIONS,
        "sys": ALL_FUNCTIONS,     # Interpreter manipulation
        "operator": [
            "attrgetter",  # Gadget chain: operator.attrgetter("system")(__import__("os"))
        ],
        "pty": ALL_FUNCTIONS,     # Pseudo-terminal utilities
        "pickle": ALL_FUNCTIONS,  # Nested pickle injection
        "_pickle": ALL_FUNCTIONS,
        "bdb": ALL_FUNCTIONS,     # Debugger (can execute code)
        "pdb": ALL_FUNCTIONS,
        "shutil": ALL_FUNCTIONS,  # File system manipulation
        "asyncio": ALL_FUNCTIONS, # Async execution
        "marshal": ALL_FUNCTIONS, # Deserialization of bytecode
    },
    "HIGH": {
        "webbrowser": ALL_FUNCTIONS,   # Can open URLs
        "httplib": ALL_FUNCTIONS,      # Legacy HTTP
        "requests.api": ALL_FUNCTIONS, # HTTP requests (exfiltration)
        "aiohttp.client": ALL_FUNCTIONS,
        "urllib": ALL_FUNCTIONS,
        "urllib2": ALL_FUNCTIONS,
    },
    "MEDIUM": {
        # Reserved for future use (e.g., heavy resource usage)
    },
    "LOW": {
        # Reserved for warnings
    },
}


def get_severity(module: str, name: str) -> Optional[str]:
    """
    Checks a module.function pair against the blocklist.
    
    Args:
        module: The module name (e.g., "os", "builtins").
        name: The function/attribute name (e.g., "system", "eval").
        
    Returns:
        Severity string ("CRITICAL", "HIGH", etc.) or None if not found.
    """
    # Check CRITICAL first, then HIGH, etc.
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        rules = UNSAFE_GLOBALS.get(severity, {})
        
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
