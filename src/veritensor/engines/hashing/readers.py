# Copyright 2025 Veritensor Security
# Logic adapted from:
# 1. gguf-py (MIT License) - for GGUF parsing
# 2. safetensors (Apache 2.0) - for Safetensors header parsing
# 3. AIsbom (Apache 2.0) - for efficient Zip/PyTorch inspection

import struct
import json
import zipfile
import logging
from typing import Dict, Any, Optional, BinaryIO
from pathlib import Path
from veritensor.core.safe_zip import SafeZipReader, ZipBombError

# --- Constants ---
GGUF_MAGIC = 0x46554747  # "GGUF" in little-endian
GGUF_DEFAULT_ALIGNMENT = 32
MAX_HEADER_SIZE = 100 * 1024 * 1024 # 100 MB Limit for Safetensors header

# Mapping GGUF value types to Python types (subset needed for metadata)
# Ref: gguf-py/constants.py
GGUF_VALUE_TYPE_UINT8 = 0
GGUF_VALUE_TYPE_INT8 = 1
GGUF_VALUE_TYPE_UINT16 = 2
GGUF_VALUE_TYPE_INT16 = 3
GGUF_VALUE_TYPE_UINT32 = 4
GGUF_VALUE_TYPE_INT32 = 5
GGUF_VALUE_TYPE_FLOAT32 = 6
GGUF_VALUE_TYPE_BOOL = 7
GGUF_VALUE_TYPE_STRING = 8
GGUF_VALUE_TYPE_ARRAY = 9
GGUF_VALUE_TYPE_UINT64 = 10
GGUF_VALUE_TYPE_INT64 = 11
GGUF_VALUE_TYPE_FLOAT64 = 12

logger = logging.getLogger(__name__)


class ModelReader:
    """
    Base class for reading model metadata without loading weights.
    """
    def read_metadata(self, file_path: Path) -> Dict[str, Any]:
        raise NotImplementedError


class SafetensorsReader(ModelReader):
    """
    Parses .safetensors files.
    Format: 8 bytes (uint64) header_length + JSON header + Data.
    """
    def read_metadata(self, file_path: Path) -> Dict[str, Any]:
        try:
            with open(file_path, "rb") as f:
                # Read the first 8 bytes to get the length of the JSON header
                length_bytes = f.read(8)
                if len(length_bytes) != 8:
                    return {"error": "File too small"}
                
                header_len = struct.unpack('<Q', length_bytes)[0]
                
                # Safety check: Header shouldn't be absurdly large (e.g., > 100MB)
                if header_len > MAX_HEADER_SIZE:
                    return {"error": f"Header too large ({header_len} bytes). Possible DoS attack or corrupted file."}

                # Read the JSON header
                header_json_bytes = f.read(header_len)
                header_data = json.loads(header_json_bytes)
                
                # Extract standard metadata if available
                metadata = header_data.get("__metadata__", {})
                
                return {
                    "format": "safetensors",
                    "metadata": metadata,
                    "tensor_count": len(header_data) - (1 if "__metadata__" in header_data else 0)
                }
        except Exception as e:
            logger.error(f"Failed to read safetensors {file_path}: {e}")
            return {"error": str(e)}


class PyTorchZipReader(ModelReader):
    """
    Parses .pt/.pth files (Zip archives).
    Checks for the existence of pickle files or data records.
    """
    def read_metadata(self, file_path: Path) -> Dict[str, Any]:
        try:
            if not zipfile.is_zipfile(file_path):
                return {"format": "pytorch_legacy", "note": "Not a zip file"}

            with zipfile.ZipFile(file_path, 'r') as z:
                # ZIP BOMB PROTECTION
                SafeZipReader.validate(z)

                file_list = z.namelist()
                has_data_pkl = "archive/data.pkl" in file_list or "data.pkl" in file_list
                has_version = "archive/version" in file_list or "version" in file_list
                
                return {
                    "format": "pytorch_zip",
                    "files": file_list,
                    "is_valid_structure": has_data_pkl and has_version
                }
        except ZipBombError as e:
            return {"error": f"Zip Bomb detected: {str(e)}"}
        except Exception as e:
            return {"error": str(e)}


class GGUFReader(ModelReader):
    """
    Parses .gguf files.
    Implements a minimal GGUF parser based on gguf-py logic.
    Reads Magic -> Version -> TensorCount -> KV Pairs.
    """
    def read_metadata(self, file_path: Path) -> Dict[str, Any]:
        try:
            with open(file_path, "rb") as f:
                # 1. Check Magic
                magic = struct.unpack('<I', f.read(4))[0]
                if magic != GGUF_MAGIC:
                    return {"error": "Invalid GGUF magic"}

                # 2. Check Version
                version = struct.unpack('<I', f.read(4))[0]
                
                # 3. Read Counts
                # GGUF v2 and v3 have different header structures regarding counts
                # But for v3 (standard): Tensor Count (Q), KV Count (Q)
                tensor_count = struct.unpack('<Q', f.read(8))[0]
                kv_count = struct.unpack('<Q', f.read(8))[0]
                
                metadata = {}
                
                # 4. Parse Key-Value Pairs
                for _ in range(kv_count):
                    key = self._read_string(f)
                    val_type = struct.unpack('<I', f.read(4))[0]
                    value = self._read_value(f, val_type)
                    
                    # Store interesting metadata
                    if isinstance(key, str):
                        # We are interested in general info, licenses, authors
                        if key.startswith("general."):
                            clean_key = key.replace("general.", "")
                            metadata[clean_key] = value

                return {
                    "format": "gguf",
                    "version": version,
                    "tensor_count": tensor_count,
                    "metadata": metadata
                }

        except Exception as e:
            logger.error(f"Failed to read GGUF {file_path}: {e}")
            return {"error": str(e)}

    def _read_string(self, f: BinaryIO) -> str:
        """Reads a GGUF string: Length (Q) + Bytes"""
        length = struct.unpack('<Q', f.read(8))[0]
        return f.read(length).decode('utf-8', errors='replace')

    def _read_value(self, f: BinaryIO, val_type: int) -> Any:
        """Reads a GGUF value based on its type ID."""
        if val_type == GGUF_VALUE_TYPE_UINT8:
            return struct.unpack('<B', f.read(1))[0]
        elif val_type == GGUF_VALUE_TYPE_INT8:
            return struct.unpack('<b', f.read(1))[0]
        elif val_type == GGUF_VALUE_TYPE_UINT16:
            return struct.unpack('<H', f.read(2))[0]
        elif val_type == GGUF_VALUE_TYPE_INT16:
            return struct.unpack('<h', f.read(2))[0]
        elif val_type == GGUF_VALUE_TYPE_UINT32:
            return struct.unpack('<I', f.read(4))[0]
        elif val_type == GGUF_VALUE_TYPE_INT32:
            return struct.unpack('<i', f.read(4))[0]
        elif val_type == GGUF_VALUE_TYPE_FLOAT32:
            return struct.unpack('<f', f.read(4))[0]
        elif val_type == GGUF_VALUE_TYPE_UINT64:
            return struct.unpack('<Q', f.read(8))[0]
        elif val_type == GGUF_VALUE_TYPE_INT64:
            return struct.unpack('<q', f.read(8))[0]
        elif val_type == GGUF_VALUE_TYPE_FLOAT64:
            return struct.unpack('<d', f.read(8))[0]
        elif val_type == GGUF_VALUE_TYPE_BOOL:
            return f.read(1) != b'\x00'
        elif val_type == GGUF_VALUE_TYPE_STRING:
            return self._read_string(f)
        elif val_type == GGUF_VALUE_TYPE_ARRAY:
            # Array format: Type (I) + Count (Q) + Values
            item_type = struct.unpack('<I', f.read(4))[0]
            item_count = struct.unpack('<Q', f.read(8))[0]
            values = []
            for _ in range(item_count):
                values.append(self._read_value(f, item_type))
            return values
        else:
            # Unknown type, we might lose sync here if we don't know size
            return "UNKNOWN_TYPE"


def get_reader_for_file(file_path: Path) -> Optional[ModelReader]:
    """Factory to get the correct reader based on extension."""
    ext = file_path.suffix.lower()
    if ext == ".safetensors":
        return SafetensorsReader()
    elif ext == ".gguf":
        return GGUFReader()
    elif ext in [".pt", ".pth", ".bin", ".ckpt", ".whl"]:
        # Check if it's a zip (modern pytorch) or legacy
        if zipfile.is_zipfile(file_path):
            return PyTorchZipReader()
        # Legacy pickle handling is done in the static analysis engine, not here
        return None
    return None
