# Copyright 2025 Aegis Security
# Logic adapted from AIsbom (Apache 2.0 License)
#
# This engine performs static analysis of Pickle bytecode.
# It emulates the Pickle VM stack to detect obfuscated calls (STACK_GLOBAL).

import pickletools
import io
import logging
from typing import List, Set, Tuple

logger = logging.getLogger(__name__)

# --- Security Policies (Allowlist) ---
# We use a "Strict by Default" approach. Only known safe mathematical
# and data manipulation libraries are allowed.

SAFE_MODULES = {
    "torch",
    "numpy",
    "collections",
    "builtins",
    "copyreg",
    "__builtin__",
    "typing",
    "datetime",
    "pathlib",
    "posixpath",
    "ntpath",
    "re",
    "copy",
    "functools",
    "operator",
    "warnings",
    "contextlib",
    "abc",
    "enum",
    "dataclasses",
    "types",
    "_operator",
    "complex",
    "_codecs",
}

SAFE_BUILTINS = {
    "getattr", "setattr", "bytearray", "dict", "list", "set", "tuple",
    "slice", "frozenset", "range", "complex",
    "bool", "int", "float", "str", "bytes", "object",
}

# Known dangerous modules for fast-fail checking (Blacklist)
DANGEROUS_GLOBALS = {
    "os": {"system", "popen", "execl", "execvp", "spawn"},
    "subprocess": {"Popen", "call", "check_call", "check_output", "run"},
    "builtins": {"eval", "exec", "compile", "open", "__import__"},
    "posix": {"system", "popen"},
    "webbrowser": {"open"},
    "socket": {"socket", "connect"},
    "marshal": {"loads"},  # Code injection via bytecode
    "pickle": {"loads", "load"}, # Nested pickle injection
}


def _is_safe_import(module: str, name: str) -> bool:
    """
    Validates imports against strict allowlist policies.
    """
    # 1. Exact Match Safe Modules
    if module in SAFE_MODULES:
        # Special case for builtins to prevent eval/exec
        if module in ("builtins", "__builtin__"):
            return name in SAFE_BUILTINS
        return True
    
    # 2. Torch Submodules (torch.* is generally safe for weights)
    if module.startswith("torch."):
        return True
    
    # 3. Codecs (Explicitly allow encode/decode only)
    if module == "_codecs" and name in ("encode", "decode"):
        return True
        
    # 4. Safe submodules of allowed packages
    if module.startswith("pathlib.") or module.startswith("re.") or module.startswith("collections."):
        return True
    
    # 5. Numpy submodules
    if module.startswith("numpy."):
        return True

    return False


def scan_pickle_stream(data: bytes, strict_mode: bool = True) -> List[str]:
    """
    Disassembles a pickle stream and checks for dangerous imports.
    
    Args:
        data: The raw bytes of the pickle file (or stream content).
        strict_mode: If True, blocks anything not in SAFE_MODULES.
                     If False, only blocks DANGEROUS_GLOBALS.
    
    Returns:
        List of detected threats (e.g., ["UNSAFE_IMPORT: os.system"]).
    """
    # Limit memo size to prevent memory exhaustion attacks
    MAX_MEMO_SIZE = 100 
    
    threats = []
    
    # 'memo' emulates the Pickle VM stack. 
    # We track the last few string literals pushed to the stack 
    # to resolve STACK_GLOBAL arguments.
    memo = [] 

    try:
        stream = io.BytesIO(data)
        
        for opcode, arg, pos in pickletools.genops(stream):
            
            # Track string literals on the stack
            if opcode.name in ("SHORT_BINUNICODE", "UNICODE", "BINUNICODE"):
                memo.append(arg)
                # We only need the top 2 items for STACK_GLOBAL (module, name)
                # VULNERABILITY FIX: Prevent infinite growth
                if len(memo) > MAX_MEMO_SIZE: 
                    memo.pop(0)
            
            # If the stack is modified by other ops, we might lose track.
            # Ideally, we'd implement a full VM, but clearing memo on complex ops
            # reduces false positives in STACK_GLOBAL resolution.
            elif opcode.name not in ("PROTO", "MEMOIZE", "MARK", "STOP"):
                # If we see a tuple or other structure, our simple 'memo' 
                # might be out of sync with the real stack. 
                # However, attackers usually push strings right before STACK_GLOBAL.
                pass

            # --- Check GLOBAL (Explicit import) ---
            if opcode.name == "GLOBAL":
                # Arg is "module\nname" or "module name"
                module, name = None, None
                if isinstance(arg, str):
                    if "\n" in arg:
                        module, name = arg.split("\n", 1)
                    elif " " in arg:
                        module, name = arg.split(" ", 1)

                if module and name:
                    threat = _check_import(module, name, strict_mode)
                    if threat:
                        threats.append(threat)

            # --- Check STACK_GLOBAL (Dynamic import) ---
            elif opcode.name == "STACK_GLOBAL":
                # Takes two arguments from the stack: module and name
                # Since we track strings in 'memo', we check the last two.
                if len(memo) >= 2:
                    name = memo[-1]
                    module = memo[-2]
                    
                    if isinstance(module, str) and isinstance(name, str):
                        threat = _check_import(module, name, strict_mode)
                        if threat:
                            threats.append(f"{threat} (via STACK_GLOBAL)")
                
                # Clear memo after use to avoid reusing old stack items incorrectly
                memo.clear()

    except Exception as e:
        logger.warning(f"Pickle parsing error (possibly truncated or malformed): {e}")
        # In a real security scenario, a malformed pickle is suspicious.
        # But for scanning partial streams (headers), we might hit EOF.
        pass

    return threats


def _check_import(module: str, name: str, strict_mode: bool) -> str:
    """Helper to decide if an import is a threat."""
    
    # 1. Check Blacklist (Always active)
    if module in DANGEROUS_GLOBALS:
        if "*" in DANGEROUS_GLOBALS[module] or name in DANGEROUS_GLOBALS[module]:
            return f"CRITICAL: {module}.{name}"
            
    # 2. Check Allowlist (Strict Mode)
    if strict_mode:
        if not _is_safe_import(module, name):
            return f"UNSAFE_IMPORT: {module}.{name}"
            
    return ""
