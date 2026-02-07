# Copyright 2025 Veritensor Security Apache 2.0
# RAG Scanner: Detects Prompt Injections, PII, and Stealth Attacks (CSS/HTML hiding).

import logging
import re 
from typing import List, Generator, Set
from pathlib import Path
from veritensor.engines.static.rules import SignatureLoader
from veritensor.engines.content.pii import PIIScanner

logger = logging.getLogger(__name__)

# Supported text formats for RAG scanning
TEXT_EXTENSIONS = {
    # Documentation & Markup
    ".txt", ".md", ".markdown", ".rst", ".adoc", ".asciidoc", 
    ".tex", ".org", ".wiki", ".html", ".htm", ".css",
    
    # Data & Configs
    ".json", ".xml", ".yaml", ".yml", ".toml", 
    ".ini", ".cfg", ".conf", ".env", ".properties", ".editorconfig",
    
    # Source Code
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp",
    ".rs", ".go", ".rb", ".php", ".pl", ".lua",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".sql",
    
    # Infrastructure
    ".dockerfile", ".tf", ".tfvars", ".k8s", ".helm", ".tpl",
    ".gitignore", ".gitattributes",
    
    # Logs
    ".log", ".out", ".err"
}

DOC_EXTS = {".pdf", ".docx", ".pptx"}

# Import Optional Dependencies
try:
    import pypdf
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import docx
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    from pptx import Presentation
    PPTX_AVAILABLE = True
except ImportError:
    PPTX_AVAILABLE = False

CHUNK_SIZE = 1024 * 1024 # 1MB chunks
OVERLAP_SIZE = 4096      # 4KB overlap

# --- STEALTH ATTACK SIGNATURES (CSS/HTML Hiding) ---
# These patterns detect attempts to hide text from humans but show it to LLMs.
STEALTH_PATTERNS = [
    r"font-size:\s*0px",
    r"font-size:\s*1px",
    r"color:\s*white",
    r"color:\s*#ffffff",
    r"color:\s*#fff",
    r"color:\s*transparent",
    r"display:\s*none",
    r"visibility:\s*hidden",
    r"opacity:\s*0",
    r"position:\s*absolute;\s*left:\s*-\d+px",
    r"z-index:\s*-\d+",
    r"<!--.*?ignore previous.*?-->", # HTML Comments with injections
    r"<span[^>]*style=.*?>.*?</span>" # Suspicious spans (generic check)
]

def scan_document(file_path: Path) -> List[str]:
    """
    Universal entry point for scanning documents (RAG Data).
    Dispatches to specific extractors based on extension.
    """
    ext = file_path.suffix.lower()
    threats = []
    
    # Load signatures (List of strings, some starting with 'regex:')
    signatures = SignatureLoader.get_prompt_injections()

    try:
        # --- PHASE 1: Raw Content Scan (Stealth Detection) ---
        # We scan the raw file bytes to find HTML/CSS hacks that parsers might strip.
        # This is critical for PDF/Docx where "color: white" is hidden in the internal structure.
        if ext in DOC_EXTS or ext in TEXT_EXTENSIONS:
            raw_threats = _scan_raw_binary(file_path)
            threats.extend(raw_threats)
            # If we found explicit stealth attacks, we can return early or continue
            if raw_threats:
                # We continue to find specific injection payloads
                pass

        # --- PHASE 2: Extracted Text Scan (Semantic Detection) ---
        # Get Text Generator (Yields chunks)
        text_generator = None
        
        if ext in TEXT_EXTENSIONS:
            text_generator = _read_text_sliding(file_path)
        elif ext == ".pdf" and PDF_AVAILABLE:
            full_text = _read_pdf(file_path)
            text_generator = _yield_string_chunks(full_text)
        elif ext == ".docx" and DOCX_AVAILABLE:
            full_text = _read_docx(file_path)
            text_generator = _yield_string_chunks(full_text)
        elif ext == ".pptx" and PPTX_AVAILABLE:
            full_text = _extract_text_from_pptx(file_path)
            text_generator = _yield_string_chunks(full_text)
        else:
            return threats # Return whatever raw threats we found

        # Scan Extracted Chunks
        for chunk in text_generator:
            if not chunk: continue

            # A. Prompt Injection Logic (Regex + Normalization)
            clean_chunk = " ".join(chunk.split())
            
            # Check for Spaced/Obfuscated keywords (e.g. "I g n o r e")
            if len(clean_chunk) > 50 and (clean_chunk.count(" ") / len(clean_chunk)) > 0.3:
                collapsed_chunk = clean_chunk.replace(" ", "")
                CRITICAL_KEYWORDS = [
                   "asananswer", "alwayswrite", "ignoreprevious", "systemoverride", 
                   "pwned", "jailbreak"
                ]
                for kw in CRITICAL_KEYWORDS:
                    if kw in collapsed_chunk.lower():
                        threats.append(f"HIGH: Obfuscated/Spaced Injection detected in {file_path.name}: '{kw}'")
                        return threats

            # Check Standard Signatures
            for pattern in signatures:
                is_hit = False
                found_text = ""
                
                if pattern.startswith("regex:"):
                    regex_str = pattern.replace("regex:", "", 1).strip()
                    try:
                        match = re.search(regex_str, clean_chunk, re.IGNORECASE)
                        if match:
                            is_hit = True
                            found_text = match.group(0)[:100]
                    except re.error:
                        logger.warning(f"Invalid regex in signatures: {regex_str}")
                else:
                    if pattern.lower() in clean_chunk.lower():
                        is_hit = True
                        found_text = pattern 
                
                if is_hit:
                    threats.append(f"HIGH: Prompt Injection detected in {file_path.name}: Found '{found_text}'")
                    return threats 

            # B. PII Scan (Presidio)
            pii_threats = PIIScanner.scan(chunk)
            if pii_threats:
                threats.extend(pii_threats)
                return threats

    except Exception as e:
        logger.warning(f"Failed to scan document {file_path}: {e}")
        threats.append(f"WARNING: Doc Scan Error: {str(e)}")
        
    return threats

# --- Helpers ---

def _scan_raw_binary(path: Path) -> List[str]:
    """
    Scans the raw bytes of a file (PDF/Docx/HTML) for CSS/HTML hiding techniques.
    Uses Latin-1 decoding to map bytes 1-to-1 to characters for Regex.
    """
    threats = []
    try:
        with open(path, "rb") as f:
            buffer = ""
            while True:
                # Read binary chunk
                chunk_bytes = f.read(CHUNK_SIZE)
                if not chunk_bytes:
                    break
                
                # Decode as Latin-1 to preserve all byte values as chars
                # This allows searching for ASCII strings inside binary files (like PDF streams)
                chunk_str = chunk_bytes.decode("latin-1")
                
                # Combine with overlap
                data = buffer + chunk_str
                
                # Check Stealth Patterns
                for pattern in STEALTH_PATTERNS:
                    if re.search(pattern, data, re.IGNORECASE):
                        threats.append(f"MEDIUM: Stealth/Hiding technique detected in {path.name} (Raw): '{pattern}'")
                        return threats # Fail fast on stealth detection
                
                # Update buffer
                buffer = chunk_str[-OVERLAP_SIZE:]
    except Exception:
        pass # Ignore binary read errors
    return threats

def _read_text_sliding(path: Path) -> Generator[str, None, None]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        buffer = ""
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            data = buffer + chunk
            yield data
            buffer = chunk[-OVERLAP_SIZE:]

def _yield_string_chunks(text: str) -> Generator[str, None, None]:
    if not text: return
    yield text

def _read_pdf(path: Path) -> str:
    text_content = []
    try:
        reader = pypdf.PdfReader(path)
        max_pages = min(len(reader.pages), 50) 
        for i in range(max_pages):
            page_text = reader.pages[i].extract_text()
            if page_text:
                text_content.append(page_text)
        return "\n".join(text_content)
    except Exception as e:
        logger.debug(f"PDF parsing error: {e}")
        return ""

def _read_docx(path: Path) -> str:
    text_content = []
    try:
        doc = docx.Document(path)
        max_paras = min(len(doc.paragraphs), 2000)
        for i in range(max_paras):
            text_content.append(doc.paragraphs[i].text)
        return "\n".join(text_content)
    except Exception as e:
        logger.debug(f"DOCX parsing error: {e}")
        return ""

def _extract_text_from_pptx(path: Path) -> str:
    if not PPTX_AVAILABLE:
        return ""
    text_runs = []
    try:
        prs = Presentation(path)
        for slide in prs.slides:
            for shape in slide.shapes:
                if hasattr(shape, "text"):
                    text_runs.append(shape.text)
    except Exception as e:
        logger.warning(f"Failed to parse PPTX {path.name}: {e}")
    return "\n".join(text_runs)
