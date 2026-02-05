# Copyright 2026 Veritensor Security Apache 2.0
# Dataset Scanner (Parquet, CSV, JSONL) for Data Poisoning & Malicious URLs

import logging
import json
import csv
import sys
from pathlib import Path
from typing import List, Generator, Optional, Any

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
MAX_JSON_LINE_SIZE = 10 * 1024 * 1024 # 10MB limit for JSONL lines (DoS protection)

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
                
            # Limit string length to prevent Regex DoS (ReDoS)
            # We truncate strictly to 4KB per cell analysis
            if len(text_chunk) > 4096:
                text_chunk = text_chunk[:4096]

            # A. Prompt Injection (Data Poisoning)
            # OPTIMIZATION: Single pass loop instead of double check
            for pat in injections:
                if is_match(text_chunk, [pat]):
                    threats.append(f"HIGH: Data Poisoning (Injection) detected in {file_path.name}: '{pat}'")
                    return threats # Fail fast

            # B. Malicious URLs / Secrets / PII
            for pat in suspicious:
                if is_match(text_chunk, [pat]):
                    # Determine label
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
    try:
        parquet_file = pq.ParquetFile(path)
    except Exception:
        return # Invalid parquet

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
    """
    Reads CSV using a hybrid approach:
    1. Uses Pandas (if available) for speed and to scan ONLY text columns.
    2. Falls back to csv stdlib for lightweight environments.
    """
    # Trying to use Pandas for smart scanning (Column Pruning)    try:
        import pandas as pd
        
        # We only read the headers to determine the data types
        header_df = pd.read_csv(path, nrows=0)
        # We find only "string" columns (of the object type)
        text_cols = header_df.select_dtypes(include=['object']).columns.tolist()
        
        if not text_cols:
            return # No text data, no threats

        # Read the file in chunks of 1000 lines
        # usecols=[...] allows  not to read unnecessary numeric data from the disk
        chunks = pd.read_csv(
            path, 
            chunksize=1000, 
            nrows=limit, 
            usecols=text_cols,
            encoding="utf-8",
            on_bad_lines="skip", # Ignoring broken lines
            low_memory=True
        )

        for chunk in chunks:
            for col in text_cols:
                # Vectorized processing via .dropna() and .astype(str)
                for val in chunk[col].dropna():
                    yield str(val)

    except ImportError:
        logger.debug(f"Pandas not found, using stdlib for {path.name}")
        
        csv.field_size_limit(min(sys.maxsize, 10 * 1024 * 1024)) 
        
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            count = 0
            try:
                for row in reader:
                    for cell in row:
                        if cell:
                            yield cell
                    
                    count += 1
                    if limit and count >= limit:
                        break
            except csv.Error as e:
                logger.warning(f"CSV Parse error in {path.name} at row {count}: {e}")

    except Exception as e:
        logger.error(f"Failed to stream CSV {path.name}: {e}")

def _stream_jsonl(path: Path, limit: Optional[int]) -> Generator[str, None, None]:
    """Reads JSONL line by line with Memory Protection."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        count = 0
        for line in f:
            # OOM PROTECTION: Skip huge lines before parsing
            if len(line) > MAX_JSON_LINE_SIZE:
                continue

            try:
                data = json.loads(line)
                yield from _extract_strings_from_json(data)
            except json.JSONDecodeError:
                pass 
            
            count += 1
            if limit and count >= limit:
                break

def _extract_strings_from_json(data: Any) -> Generator[str, None, None]:
    """
    Iterative (Stack-based) extraction to prevent RecursionError on deep JSON.
    """
    stack = [data]
    
    while stack:
        current = stack.pop()
        
        if isinstance(current, str):
            yield current
        elif isinstance(current, dict):
            # Push values to stack
            stack.extend(current.values())
        elif isinstance(current, list):
            # Push items to stack
            stack.extend(current)
