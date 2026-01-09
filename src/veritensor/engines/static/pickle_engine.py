# Copyright 2025 Veritensor Security
# Logic adapted from AIsbom (Apache 2.0 License)
#
# This engine performs static analysis of Pickle bytecode.
# It emulates the Pickle VM stack to detect obfuscated calls (STACK_GLOBAL)
# and scans for suspicious string constants (secrets/paths).

import pickletools
import io
import logging
from typing import List

# Import dynamic rules loader
from veritensor.engines.static.rules import get_severity

logger = logging.getLogger(__name__)

# --- Security Policies (Allowlist) ---
# Used only when strict_mode=True.
# We keep the allowlist hardcoded here as it defines the "Safe Baseline" for ML models.
SAFE_MODULES = {
    "torch", "numpy", "collections", "builtins", "copyreg", "typing",
    "datetime", "pathlib", "posixpath", "ntpath", "re", "copy",
    "functools", "operator", "warnings", "contextlib", "abc", "enum",
    "dataclasses", "types", "_operator", "complex", "_codecs",
    "pytorch_lightning", "sklearn", "pandas", "scipy"
}

SAFE_BUILTINS = {
    "getattr", "setattr", "bytearray", "dict", "list", "set", "tuple",
    "slice", "frozenset", "range", "complex", "bool", "int", "float", 
    "str", "bytes", "object", "print"
}

# --- Heuristics (Suspicious Strings) ---
# These patterns indicate potential credential theft or reconnaissance
SUSPICIOUS_STRINGS = [
    "/etc/passwd", "/etc/shadow", 
    ".ssh/id_rsa", ".ssh/known_hosts",
    ".aws/credentials", ".aws/config",
    "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY",
    "OPENAI_API_KEY", "HF_TOKEN",
    "169.254.169.254", # AWS Metadata IP
    "metadata.google.internal",
    "ngrok", "pastebin"
]

def _is_safe_import(module: str, name: str) -> bool:
    """Checks if the module is in the strict allowlist."""
    if module in SAFE_MODULES:
        if module in ("builtins", "__builtin__"):
            return name in SAFE_BUILTINS
        return True
    
    # Allow submodules of safe packages
    if module.startswith("torch.") or module.startswith("numpy."):
        return True
    if module.startswith("pathlib.") or module.startswith("re.") or module.startswith("collections."):
        return True
    
    return False

def scan_pickle_stream(data: bytes, strict_mode: bool = True) -> List[str]:
    """
    Disassembles a pickle stream and checks for dangerous imports and patterns.
    """
    # Increased limit to prevent false positives on deep PyTorch models
    MAX_MEMO_SIZE = 2048 
    
    threats = []
    memo = [] 

    try:
        stream = io.BytesIO(data)
        for opcode, arg, pos in pickletools.genops(stream):
            
            # --- 1. Track String Literals (Stack Emulation) ---
            if opcode.name in ("SHORT_BINUNICODE", "UNICODE", "BINUNICODE"):
                memo.append(arg)
                if len(memo) > MAX_MEMO_SIZE: 
                    memo.pop(0)
                
                # --- 2. Heuristic Check: Suspicious Strings ---
                # Check if the string itself is a known IOC (Indicator of Compromise)
                if isinstance(arg, str):
                    for pattern in SUSPICIOUS_STRINGS:
                        if pattern in arg:
                            threats.append(f"HIGH: Suspicious string detected: '{arg}'")

            # Reset memo on STOP to clear stack between multiple pickles in one file
            elif opcode.name == "STOP":
                memo.clear()

            # --- 3. Check GLOBAL (Explicit Import) ---
            elif opcode.name == "GLOBAL":
                # Arg format: "module\nname" or "module name"
                module, name = None, None
                if isinstance(arg, str):
                    if "\n" in arg:
                        module, name = arg.split("\n", 1)
                    elif " " in arg:
                        module, name = arg.split(" ", 1)
                
                if module and name:
                    threat = _check_import(module, name, strict_mode)
                    if threat: threats.append(threat)

            # --- 4. Check STACK_GLOBAL (Dynamic Import) ---
            elif opcode.name == "STACK_GLOBAL":
                # Takes top 2 items from stack: module, name
                if len(memo) >= 2:
                    name = memo[-1]
                    module = memo[-2]
                    
                    if isinstance(module, str) and isinstance(name, str):
                        threat = _check_import(module, name, strict_mode)
                        if threat: threats.append(f"{threat} (via STACK_GLOBAL)")
                
                # Clear memo after usage to prevent confusion in complex object graphs
                memo.clear() 

    except Exception as e:
        # We do not crash on malformed files
        pass

    return threats

def _check_import(module: str, name: str, strict_mode: bool) -> str:
    """
    Decides if an import is a threat using Blocklist (rules.py) and Allowlist.
    """
    # 1. Check Blocklist (Signatures from rules.py/signatures.yaml)
    # This detects known malware (CRITICAL/HIGH)
    severity = get_severity(module, name)
    if severity:
        return f"{severity}: {module}.{name}"

    # 2. Check Allowlist (Strict Mode)
    # This detects unknown/anomalous imports (Zero-Trust)
    if strict_mode:
        if not _is_safe_import(module, name):
            return f"UNSAFE_IMPORT: {module}.{name}"
            
    return ""
