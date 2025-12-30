# Copyright 2025 Aegis Security
# Logic adapted from ModelScan (Apache 2.0 License)
#
# This engine scans Keras models (.h5, .keras) for "Lambda" layers.
# Lambda layers can contain serialized Python bytecode, leading to RCE.

import json
import zipfile
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Try to import h5py for legacy H5 support.
# It is not a hard dependency for the CLI if only scanning .keras (zip) files.
try:
    import h5py
    H5PY_AVAILABLE = True
except ImportError:
    H5PY_AVAILABLE = False


def scan_keras_file(file_path: Path) -> List[str]:
    """
    Scans a Keras model file for malicious configurations.
    Supports both legacy HDF5 (.h5) and modern Keras v3 (.keras/zip) formats.

    Args:
        file_path: Path to the model file.

    Returns:
        List of detected threats (e.g., ["CRITICAL: Found Keras Lambda layer"]).
    """
    threats = []
    
    # 1. Try to detect format
    if zipfile.is_zipfile(file_path):
        threats.extend(_scan_keras_zip(file_path))
    elif _is_hdf5(file_path):
        if H5PY_AVAILABLE:
            threats.extend(_scan_keras_h5(file_path))
        else:
            logger.warning(f"Skipping H5 scan for {file_path}: 'h5py' not installed.")
            threats.append("WARNING: h5py missing, cannot scan legacy .h5 file")
    
    return threats


def _is_hdf5(file_path: Path) -> bool:
    """Check magic bytes for HDF5."""
    try:
        with open(file_path, "rb") as f:
            # HDF5 magic signature: \x89HDF\r\n\x1a\n
            sig = f.read(8)
            return sig == b'\x89HDF\r\n\x1a\n'
    except Exception:
        return False


def _scan_keras_zip(file_path: Path) -> List[str]:
    """
    Scans modern .keras (Zip) files.
    Logic adapted from ModelScan `KerasLambdaDetectScan`.
    """
    threats = []
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            # Keras v3 stores config in 'config.json'
            if "config.json" in z.namelist():
                with z.open("config.json") as f:
                    config_data = json.load(f)
                    threats.extend(_analyze_model_config(config_data))
            
            # Older SavedModel format might be inside zip? 
            # Usually SavedModel is a directory, but if zipped:
            # We focus on config.json for Keras v3.
            
    except Exception as e:
        logger.error(f"Error scanning Keras zip {file_path}: {e}")
        
    return threats


def _scan_keras_h5(file_path: Path) -> List[str]:
    """
    Scans legacy .h5 files using h5py.
    Logic adapted from ModelScan `H5LambdaDetectScan`.
    """
    threats = []
    try:
        with h5py.File(file_path, "r") as f:
            if "model_config" in f.attrs:
                # model_config in H5 is a JSON string stored in attributes
                config_str = f.attrs["model_config"]
                if isinstance(config_str, bytes):
                    config_str = config_str.decode("utf-8")
                
                config_data = json.loads(config_str)
                threats.extend(_analyze_model_config(config_data))
                
    except Exception as e:
        logger.error(f"Error scanning Keras H5 {file_path}: {e}")

    return threats


def _analyze_model_config(config: Dict[str, Any]) -> List[str]:
    """
    Recursively searches the model configuration for Lambda layers.
    """
    threats = []
    
    # The config structure usually has a 'config' key which contains 'layers'
    # But sometimes it's the root. We normalize.
    model_config = config.get("config", config)
    layers = model_config.get("layers", [])
    
    if not isinstance(layers, list):
        return []

    for layer in layers:
        class_name = layer.get("class_name")
        
        # --- CHECK 1: Lambda Layers ---
        # Lambda layers deserialize Python bytecode. This is RCE.
        if class_name == "Lambda":
            threats.append("CRITICAL: Keras Lambda layer detected (RCE Risk)")
            
            # Optional: Extract function code if possible for deeper analysis
            # func_config = layer.get("config", {}).get("function", {})
            # if func_config:
            #    threats.append(f"  > Payload: {str(func_config)[:50]}...")

        # --- CHECK 2: Recursion (Nested Models) ---
        # Sometimes a layer is a wrapper for another model
        if class_name in ["Model", "Functional", "Sequential"]:
            nested_config = layer.get("config", {})
            threats.extend(_analyze_model_config(nested_config))

    return threats
