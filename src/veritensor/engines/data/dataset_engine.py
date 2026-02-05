# Copyright 2026 Veritensor Security Apache 2.0
# Dataset Scanner (Parquet, CSV, JSONL) for Data Poisoning & Malicious URLs

import logging
import json
import csv
from pathlib import Path
from typing import List, Generator, Optional

from veritensor.engines.static.rules import SignatureLoader, is_match

logger = logging.getLogger(__name__)

# Optional Imports (Lazy Loading)
try:
    import pyarrow.parquet as pq
    import pyarrow as pa
    PYARROW_AVAILABLE = True
except ImportError:
    PYARROW_AVAILABLE = False

# Config
MAX_ROWS_DEFAULT = 10_000  # Quick scan limit (Sampling)
CHUNK_SIZE = 1000          # Rows per batch

def scan_dataset(file_path: Path, full_scan: bool = False) -> List[str]:
    """
    Scans datasets for Malicious URLs, Prompt Injections, and Secrets.
    Supports: .parquet, .csv, .jsonl
    """
    ext = file_path.suffix.lower()
    threats = []
    
    # Load Signatures
    injections = SignatureLoader.get_prompt_injections()
    suspicious = SignatureLoader.get_suspicious_strings() # Secrets + Malicious URLs
    
    # Limit rows unless forced (Sampling Strategy)
    row_limit = None if full_scan else MAX_ROWS_DEFAULT
    
    try:
        # 1. Get Text Generator based on format
        text_stream = None
        
        if ext == ".parquet":
            if not PYARROW_AVAILABLE:
                return ["WARNING: pyarrow not installed. Run 'pip install veritensor[data]'"]
            text_stream = _stream_parquet(file_path, row_limit)
            
        elif ext == ".csv":
            text_stream = _stream_csv(file_path, row_limit)
            
        elif ext == ".jsonl":
            text_stream = _stream_jsonl(file_path, row_limit)
            
        else:
            return [] # Not a dataset

        # 2. Scan the stream
        row_count = 0
        for text_chunk in text_stream:
            if not text_chunk or len(text_chunk) < 5:
                continue
                
            # Limit string length to prevent Regex DoS
            if len(text_chunk) > 4096:
                text_chunk = text_chunk[:4096]

            # A. Prompt Injection (Data Poisoning)
            if is_match(text_chunk, injections):
                for pat in injections:
                    if is_match(text_chunk, [pat]):
                        threats.append(f"HIGH: Data Poisoning (Injection) detected in {file_path.name}: '{pat}'")
                        return threats # Fail fast

            # B. Malicious URLs / Secrets / PII
            if is_match(text_chunk, suspicious):
                for pat in suspicious:
                    if is_match(text_chunk, [pat]):
                        # Определяем тип угрозы по паттерну
                        label = "Malicious URL" if "http" in pat else "Secret/PII"
                        threats.append(f"MEDIUM: {label} detected in dataset {file_path.name}: '{pat}'")
            
            row_count += 1
            if row_limit and row_count >= row_limit:
                break
                
    except Exception as e:
        logger.warning(f"Failed to scan dataset {file_path}: {e}")
        threats.append(f"WARNING: Dataset Scan Error: {str(e)}")

    return threats

def _stream_parquet(path: Path, limit: Optional[int]) -> Generator[str, None, None]:
    """Reads Parquet file batch by batch, yielding ONLY string columns."""
    parquet_file = pq.ParquetFile(path)
    
    # Identify string columns to avoid scanning integers/floats (Optimization)
    str_columns = []
    for i, field in enumerate(parquet_file.schema_arrow):
        if pa.types.is_string(field.type) or pa.types.is_large_string(field.type):
            str_columns.append(field.name)
            
    if not str_columns:
        return

    # Iterate batches
    count = 0
    for batch in parquet_file.iter_batches(batch_size=CHUNK_SIZE, columns=str_columns):
        for col_name in str_columns:
            column_data = batch[col_name]
            for val in column_data:
                if val is not None:
                    yield str(val)
        
        count += CHUNK_SIZE
        if limit and count >= limit:
            break

def _stream_csv(path: Path, limit: Optional[int]) -> Generator[str, None, None]:
    """Reads CSV using stdlib (Memory Safe)."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        count = 0
        for row in reader:
            for cell in row:
                yield cell
            count += 1
            if limit and count >= limit:
                break

def _stream_jsonl(path: Path, limit: Optional[int]) -> Generator[str, None, None]:
    """Reads JSONL line by line."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        count = 0
        for line in f:
            try:
                data = json.loads(line)
                yield from _extract_strings_from_json(data)
            except json.JSONDecodeError:
                pass 
            
            count += 1
            if limit and count >= limit:
                break

def _extract_strings_from_json(data) -> Generator[str, None, None]:
    if isinstance(data, str):
        yield data
    elif isinstance(data, dict):
        for value in data.values():
            yield from _extract_strings_from_json(value)
    elif isinstance(data, list):
        for item in data:
            yield from _extract_strings_from_json(item)
