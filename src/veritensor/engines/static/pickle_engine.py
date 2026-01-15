# Copyright 2025 Veritensor Security
# Logic adapted from AIsbom (Apache 2.0 License)
#
# This engine performs static analysis of Pickle bytecode.
# It emulates the Pickle VM stack to detect obfuscated calls (STACK_GLOBAL)
# and scans for suspicious string constants (secrets/paths).

import pickletools
import io
import logging
import zipfile  
from typing import List

# Import dynamic rules loader
from veritensor.engines.static.rules import get_severity

logger = logging.getLogger(__name__)

# --- Security Policies (Allowlist) ---
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

SUSPICIOUS_STRINGS = [
    "/etc/passwd", "/etc/shadow", 
    ".ssh/id_rsa", ".ssh/known_hosts",
    ".aws/credentials", ".aws/config",
    "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY",
    "OPENAI_API_KEY", "HF_TOKEN",
    "169.254.169.254",
    "metadata.google.internal",
    "ngrok", "pastebin"
]

def _is_safe_import(module: str, name: str) -> bool:
    if module in SAFE_MODULES:
        if module in ("builtins", "__builtin__"):
            return name in SAFE_BUILTINS
        return True
    if module.startswith("torch.") or module.startswith("numpy."):
        return True
    if module.startswith("pathlib.") or module.startswith("re.") or module.startswith("collections."):
        return True
    return False

def scan_pickle_stream(data: bytes, strict_mode: bool = True) -> List[str]:
    """
    Disassembles a pickle stream (or PyTorch Zip) and checks for dangerous imports.
    """
    threats = []
    
# --- PyTorch Zip Handling ---
    if data.startswith(b'PK'):
        try:
            with zipfile.ZipFile(io.BytesIO(data), 'r') as z:

                pickle_files = [n for n in z.namelist() if n.endswith('.pkl') or 'data' in n]
                
                if not pickle_files:

                    pass
                
                for pkl_name in pickle_files:
                    try:
                        with z.open(pkl_name) as f:
        
                            inner_data = f.read()
                       
                            threats.extend(scan_pickle_stream(inner_data, strict_mode))
                    except Exception:
                        continue
            

            return list(set(threats)) 
            
        except zipfile.BadZipFile:
            pass 

    # --- Standard Pickle Scanning ---
    MAX_MEMO_SIZE = 2048 
    memo = [] 

    try:
        stream = io.BytesIO(data)
        for opcode, arg, pos in pickletools.genops(stream):
            
            if opcode.name in ("SHORT_BINUNICODE", "UNICODE", "BINUNICODE"):
                memo.append(arg)
                if len(memo) > MAX_MEMO_SIZE: 
                    memo.pop(0)
                
                if isinstance(arg, str):
                    for pattern in SUSPICIOUS_STRINGS:
                        if pattern in arg:
                            threats.append(f"HIGH: Suspicious string detected: '{arg}'")

            elif opcode.name == "STOP":
                memo.clear()

            elif opcode.name == "GLOBAL":
                module, name = None, None
                if isinstance(arg, str):
                    if "\n" in arg:
                        module, name = arg.split("\n", 1)
                    elif " " in arg:
                        module, name = arg.split(" ", 1)
                
                if module and name:
                    threat = _check_import(module, name, strict_mode)
                    if threat: threats.append(threat)

            elif opcode.name == "STACK_GLOBAL":
                if len(memo) >= 2:
                    name = memo[-1]
                    module = memo[-2]
                    if isinstance(module, str) and isinstance(name, str):
                        threat = _check_import(module, name, strict_mode)
                        if threat: threats.append(f"{threat} (via STACK_GLOBAL)")
                memo.clear() 

    except Exception as e:
  
        pass

    return threats

def _check_import(module: str, name: str, strict_mode: bool) -> str:
    severity = get_severity(module, name)
    if severity:
        return f"{severity}: {module}.{name}"

    if strict_mode:
        if not _is_safe_import(module, name):
            return f"UNSAFE_IMPORT: {module}.{name}"
            
    return ""
