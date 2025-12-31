# Copyright 2025 Aegis Security
# Logic adapted from ModelScan (Apache 2.0 License)
#
# This engine scans Keras models (.h5, .keras) for "Lambda" layers.
# Lambda layers can contain serialized Python bytecode, leading to RCE.
# Patched against Zip Bombs (DoS)

import json
import zipfile
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Max size for config files (10 MB is huge for a JSON config)
MAX_CONFIG_SIZE = 10 * 1024 * 1024 

try:
    import h5py
    H5PY_AVAILABLE = True
except ImportError:
    H5PY_AVAILABLE = False

def scan_keras_file(file_path: Path) -> List[str]:
    threats = []
    try:
        if zipfile.is_zipfile(file_path):
            threats.extend(_scan_keras_zip(file_path))
        elif _is_hdf5(file_path):
            if H5PY_AVAILABLE:
                threats.extend(_scan_keras_h5(file_path))
            else:
                threats.append("WARNING: h5py missing, cannot scan legacy .h5 file")
    except Exception as e:
        threats.append(f"Scan Error: {str(e)}")
    return threats

def _is_hdf5(file_path: Path) -> bool:
    try:
        with open(file_path, "rb") as f:
            return f.read(8) == b'\x89HDF\r\n\x1a\n'
    except Exception:
        return False

def _safe_read_json(file_obj) -> Dict[str, Any]:
    """Reads JSON with a hard size limit to prevent DoS."""
    data = file_obj.read(MAX_CONFIG_SIZE)
    if len(file_obj.read(1)) > 0: # Try reading one more byte
        raise ValueError("Config file too large (Zip Bomb protection)")
    return json.loads(data)

def _scan_keras_zip(file_path: Path) -> List[str]:
    threats = []
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            if "config.json" in z.namelist():
                # VULNERABILITY FIX: Use _safe_read_json instead of direct json.load
                with z.open("config.json") as f:
                    config_data = _safe_read_json(f)
                    threats.extend(_analyze_model_config(config_data))
    except Exception as e:
        logger.error(f"Error scanning Keras zip {file_path}: {e}")
    return threats

def _scan_keras_h5(file_path: Path) -> List[str]:
    threats = []
    try:
        with h5py.File(file_path, "r") as f:
            if "model_config" in f.attrs:
                config_str = f.attrs["model_config"]
                if isinstance(config_str, bytes):
                    config_str = config_str.decode("utf-8")
                # H5 attributes are loaded into memory by h5py, usually safe-ish,
                # but good to wrap in try-catch block handled by caller.
                config_data = json.loads(config_str)
                threats.extend(_analyze_model_config(config_data))
    except Exception as e:
        logger.error(f"Error scanning Keras H5 {file_path}: {e}")
    return threats

def _analyze_model_config(config: Dict[str, Any]) -> List[str]:
    threats = []
    # Handle both root config and nested 'config' key
    model_config = config.get("config", config)
    
    # Some configs are lists (e.g. Sequential), some dicts
    layers = model_config.get("layers", []) if isinstance(model_config, dict) else []
    
    if not isinstance(layers, list):
        return []

    for layer in layers:
        if not isinstance(layer, dict): continue
        class_name = layer.get("class_name")
        
        if class_name == "Lambda":
            threats.append("CRITICAL: Keras Lambda layer detected (RCE Risk)")
        
        if class_name in ["Model", "Functional", "Sequential"]:
            nested_config = layer.get("config", {})
            threats.extend(_analyze_model_config(nested_config))
            
    return threats
