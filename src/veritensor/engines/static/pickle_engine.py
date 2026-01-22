# Copyright 2025 Veritensor Security
# Logic adapted from AIsbom (Apache 2.0 License)
#
# This engine performs static analysis of Pickle bytecode.
# It emulates the Pickle VM stack to detect obfuscated calls (STACK_GLOBAL)
# and scans for suspicious string constants (secrets/paths) using Regex signatures.

import pickletools
import io
import logging
import zipfile  
from typing import List

# Import dynamic rules loader and regex matcher
from veritensor.engines.static.rules import get_severity, SignatureLoader, is_match

logger = logging.getLogger(__name__)

# --- Security Policies (Allowlist) ---
# Used only when strict_mode=True.
SAFE_MODULES = {
    # --- Standard Python Libs ---
    "builtins", "copyreg", "typing", "collections", "datetime",
    "pathlib", "posixpath", "ntpath", "re", "copy", "functools",
    "operator", "warnings", "contextlib", "abc", "enum", "dataclasses",
    "types", "_operator", "complex", "_codecs", "math", "random", "itertools",
    "__builtin__", 
    
    # --- Scientific Computing & ML Core ---
    "torch", "numpy", "scipy", "pandas", "sklearn", "joblib",
    
    # --- Deep Learning Frameworks ---
    "pytorch_lightning", "jax", "flax", "tensorflow", "keras",
    
    # --- Hugging Face Ecosystem ---
    "transformers", "tokenizers", "datasets", "safetensors", "huggingface_hub",
    
    # --- Computer Vision ---
    "PIL", "torchvision",
    
    # --- Configs & Utils ---
    "omegaconf", "tqdm"
}

SAFE_BUILTINS = {
    "getattr", "setattr", "bytearray", "dict", "list", "set", "tuple",
    "slice", "frozenset", "range", "complex", "bool", "int", "float", 
    "str", "bytes", "object", "print"
}

def _is_safe_import(module: str, name: str) -> bool:
    """Checks if the module is in the strict allowlist."""
    
    if module in SAFE_MODULES:
        if module in ("builtins", "__builtin__"):
            return name in SAFE_BUILTINS
        return True
    
    base_module = module.split(".")[0]
    if base_module in SAFE_MODULES and base_module not in ("builtins", "__builtin__"):
        return True
    
    if module.startswith("torch.") or module.startswith("numpy."):
        return True
    
    return False

def scan_pickle_stream(data: bytes, strict_mode: bool = True) -> List[str]:
    """
    Disassembles a pickle stream (or Zip/Wheel) and checks for dangerous imports.
    """
    threats = []
    
    # Load signatures dynamically from YAML
    suspicious_patterns = SignatureLoader.get_suspicious_strings()
    
    # --- Zip / Wheel / PyTorch Handling ---
    if data.startswith(b'PK'):
        try:
            with zipfile.ZipFile(io.BytesIO(data), 'r') as z:
                file_list = z.namelist()

                # 1. Look for Pickle files
                pickle_files = [n for n in file_list if n.endswith('.pkl') or 'data' in n]
                
                # 2. Look for Python scripts in Wheels
                script_files = [n for n in file_list if n.endswith('.py')]

                # Scan Pickles recursively
                for pkl_name in pickle_files:
                    try:
                        with z.open(pkl_name) as f:
                            inner_data = f.read()
                            threats.extend(scan_pickle_stream(inner_data, strict_mode))
                    except Exception:
                        continue

                # Scan Scripts (Heuristics)
                for script_name in script_files:
                    try:
                        with z.open(script_name) as f:
                            # Read text content (limit 1MB per script)
                            content = f.read(1024 * 1024).decode('utf-8', errors='ignore')
                            
                            # Check against suspicious patterns
                            if is_match(content, suspicious_patterns):
                                for pat in suspicious_patterns:
                                    if is_match(content, [pat]):
                                        threats.append(f"HIGH: Suspicious string in {script_name}: '{pat}'")
                                        
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
                
                # Check suspicious strings in pickle constants
                if isinstance(arg, str) and suspicious_patterns:
                    if is_match(arg, suspicious_patterns):
                         for pat in suspicious_patterns:
                            if is_match(arg, [pat]):
                                safe_arg = arg[:50] + "..." if len(arg) > 50 else arg
                                threats.append(f"HIGH: Suspicious string detected: '{pat}' in '{safe_arg}'")
                               
                                

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
