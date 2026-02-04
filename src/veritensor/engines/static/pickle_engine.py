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
from typing import List, Union, BinaryIO

# Import dynamic rules loader and regex matcher
from veritensor.engines.static.rules import get_severity, SignatureLoader, is_match
from veritensor.core.safe_zip import SafeZipReader, ZipBombError

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

def scan_pickle_stream(data: Union[bytes, BinaryIO], strict_mode: bool = True) -> List[str]:
    """
    Disassembles a pickle stream (or Zip/Wheel) and checks for dangerous imports.
    Supports both bytes (legacy) and file-like objects (streaming).
    """
    threats = []
    
    # Load signatures dynamically from YAML
    suspicious_patterns = SignatureLoader.get_suspicious_strings()
    
    # Prepare the stream
    if isinstance(data, bytes):
        stream = io.BytesIO(data)
    else:
        stream = data

    # Check for Zip file (PK header)
    # We only try to read/seek if the stream supports it.
    # ZipExtFile (used in recursive scan) is NOT seekable, so we skip this check for inner files.
    header = b""
    if hasattr(stream, "seekable") and stream.seekable():
        try:
            start_pos = stream.tell()
            header = stream.read(4)
            stream.seek(start_pos) # Reset cursor
        except Exception:
            # If stream is not seekable (e.g. pipe), assume standard pickle
            header = b""

    # --- Zip / Wheel / PyTorch Handling ---
    if header.startswith(b'PK'):
        try:
            with zipfile.ZipFile(stream, 'r') as z:
                # ZIP BOMB PROTECTION
                SafeZipReader.validate(z)

                file_list = z.namelist()
                pickle_files = [n for n in file_list if n.endswith('.pkl') or 'data' in n]
                script_files = [n for n in file_list if n.endswith('.py')]

                for pkl_name in pickle_files:
                    try:
                        with z.open(pkl_name) as f:
                            threats.extend(scan_pickle_stream(f, strict_mode))
                    except Exception:
                        continue

                for script_name in script_files:
                    try:
                        with z.open(script_name) as f:
                            content = f.read(1024 * 1024).decode('utf-8', errors='ignore')
                            if is_match(content, suspicious_patterns):
                                for pat in suspicious_patterns:
                                    if is_match(content, [pat]):
                                        threats.append(f"HIGH: Suspicious string in {script_name}: '{pat}'")
                    except Exception:
                        continue

            return list(set(threats)) 
            
        except ZipBombError as e:
            return [f"CRITICAL: DoS Attack Detected (Zip Bomb): {str(e)}"]
        except zipfile.BadZipFile:
            pass 
        except Exception:
            pass

    # --- Standard Pickle Scanning ---
    # Ensure stream is at start if we moved it (only if seekable)
    if hasattr(stream, "seekable") and stream.seekable():
        try:
            stream.seek(start_pos)
        except Exception:
            pass

    MAX_MEMO_SIZE = 2048 
    memo = [] 

    try:
        # pickletools.genops reads from the stream incrementally
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
        # Pickle parsing errors are common in non-pickle files, ignore unless debugging
        pass

    return list(set(threats))

def _check_import(module: str, name: str, strict_mode: bool) -> str:
    severity = get_severity(module, name)
    if severity:
        return f"{severity}: {module}.{name}"

    if strict_mode:
        if not _is_safe_import(module, name):
            return f"UNSAFE_IMPORT: {module}.{name}"
            
    return ""
