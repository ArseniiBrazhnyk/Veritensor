# Copyright 2026 Veritensor Security Apache 2.0
# Jupyter Notebook Scanner (.ipynb)

import json
import ast
import logging
from pathlib import Path
from typing import List
from veritensor.engines.static.rules import get_severity, SignatureLoader, is_match

logger = logging.getLogger(__name__)

# Jupyter "Magic" commands that execute shell code
DANGEROUS_MAGICS = [
    "!", "%%bash", "%%sh", "%%script", "%%perl", "%%ruby", "%system"
]

def scan_notebook(file_path: Path) -> List[str]:
    """
    Parses .ipynb JSON and scans code/output cells for threats.
    """
    threats = []
    try:
        # Читаем файл
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                nb_data = json.load(f)
            except json.JSONDecodeError:
                return ["WARNING: Invalid JSON in .ipynb file"]
            
        if "cells" not in nb_data:
            return [] # Not a valid notebook structure

        # Uploading signatures (secrets, tokens)
        suspicious_patterns = SignatureLoader.get_suspicious_strings()

        for i, cell in enumerate(nb_data["cells"]):
            cell_type = cell.get("cell_type", "")
            source_lines = cell.get("source", [])
            
            # Normalization: the source can be a list of strings or a single string
            if isinstance(source_lines, list):
                source_text = "".join(source_lines)
            else:
                source_text = str(source_lines)

            # --- 1. Scan Code Cells ---
            if cell_type == "code":
                # A. Check for Shell Injections (Magics)
                for line in source_text.splitlines():
                    stripped = line.strip()
                    for magic in DANGEROUS_MAGICS:
                        # Check that the magic is at the beginning of the line
                        if stripped.startswith(magic):
                            threats.append(f"HIGH: Jupyter Magic execution detected in cell {i+1}: '{stripped[:50]}'")

                # B. Static Analysis (AST)
                # Clearing the magic so that the Python AST parser doesn't crash
                clean_source = _clean_magics(source_text)
                if clean_source.strip():
                    try:
                        tree = ast.parse(clean_source)
                        threats.extend(_scan_ast_nodes(tree, cell_index=i+1))
                    except SyntaxError:
                        # It's okay if the code in the cell is invalid or it's not Python.
                        pass
                    except Exception as e:
                        logger.debug(f"AST Parse error in cell {i+1}: {e}")

            # --- 2. Scan All Cells (Secrets Search) ---
            # Looking for secrets in the source code of the cell
            if is_match(source_text, suspicious_patterns):
                for pat in suspicious_patterns:
                    if is_match(source_text, [pat]):
                        threats.append(f"CRITICAL: Secret/Suspicious string in cell {i+1} source: '{pat}'")

            # --- 3. Scan Outputs (Leaked keys in logs) ---
            if cell_type == "code" and "outputs" in cell:
                for output in cell["outputs"]:
                    text_content = ""
                    # Outputs come in different types (stream, execute_result, error)
                    if "text" in output:
                        # This is usually a stream (stdout/stderr)
                        content = output["text"]
                        text_content = "".join(content) if isinstance(content, list) else str(content)
                    elif "data" in output and "text/plain" in output["data"]:
                        # This is execute_result
                        content = output["data"]["text/plain"]
                        text_content = "".join(content) if isinstance(content, list) else str(content)
                    
                    # We are NOT scanning image/png or application/json here (Performance)
                    
                    if text_content and is_match(text_content, suspicious_patterns):
                        for pat in suspicious_patterns:
                            if is_match(text_content, [pat]):
                                threats.append(f"CRITICAL: Leaked secret in cell {i+1} OUTPUT: '{pat}'")

    except Exception as e:
        logger.warning(f"Error scanning notebook {file_path}: {e}")
        threats.append(f"WARNING: Scan error: {str(e)}")

    return threats

def _clean_magics(source: str) -> str:
    """Removes Jupyter magic commands (%) so AST can parse the rest."""
    lines = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("!") or stripped.startswith("%"):
            lines.append("# " + line) # We comment to save the line numbers.
        else:
            lines.append(line)
    return "\n".join(lines)

def _scan_ast_nodes(tree: ast.AST, cell_index: int) -> List[str]:
    """Traverses AST to find dangerous function calls."""
    threats = []
    
    for node in ast.walk(tree):
        # 1. Check Imports
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = []
            if isinstance(node, ast.Import):
                names = [n.name for n in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            
            for name in names:
                # Using the existing get_severity logic
                severity = get_severity(name, "*")
                if severity == "CRITICAL":
                    threats.append(f"CRITICAL: Unsafe import in cell {cell_index}: '{name}'")

        # 2. Check Function Calls (os.system, subprocess.call)
        if isinstance(node, ast.Call):
            # case: os.system() -> Attribute
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    module = node.func.value.id
                    method = node.func.attr
                    severity = get_severity(module, method)
                    if severity:
                        threats.append(f"{severity}: Dangerous call in cell {cell_index}: {module}.{method}()")
            
            # case: eval() -> Name
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id
                severity = get_severity("builtins", func_name)
                if severity:
                    threats.append(f"{severity}: Dangerous call in cell {cell_index}: {func_name}()")
                    
    return threats
