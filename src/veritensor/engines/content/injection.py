# Copyright 2025 Veritensor Security Apache 2.0
# RAG Scanner: Detects Prompt Injections in text, PDF, and Docx files.

import logging
from typing import List
from pathlib import Path
from veritensor.engines.static.rules import SignatureLoader, is_match

logger = logging.getLogger(__name__)

# Supported text formats for RAG scanning
TEXT_EXTENSIONS = {
    # Documentation & Markup
    ".txt", ".md", ".markdown", ".rst", ".adoc", ".asciidoc", 
    ".tex", ".org", ".wiki",
    
    # Data & Configs
    ".json", ".csv", ".xml", ".yaml", ".yml", ".toml", 
    ".ini", ".cfg", ".conf", ".env", ".properties", ".editorconfig",
    ".tsv", ".ndjson", ".jsonl", ".ldjson",
    
    # Source Code (Scripts)
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp",
    ".rs", ".go", ".rb", ".php", ".pl", ".lua",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".sql",
    
    # Infrastructure & DevOps
    ".dockerfile", ".tf", ".tfvars", ".k8s", ".helm", ".tpl",
    ".gitignore", ".gitattributes",
    
    # Logs
    ".log", ".out", ".err"
}

DOC_EXTENSIONS = {".pdf", ".docx"}

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


def scan_document(file_path: Path) -> List[str]:
    """
    Universal entry point for scanning documents (RAG Data).
    Dispatches to specific extractors based on extension.
    """
    ext = file_path.suffix.lower()
    content = ""
    threats = []

    try:
        # 1. Extraction Strategy
        if ext in TEXT_EXTS:
            content = _read_text(file_path)
        elif ext == ".pdf":
            if not PDF_AVAILABLE:
                return ["WARNING: pypdf not installed. Skipping PDF scan."]
            content = _read_pdf(file_path)
        elif ext == ".docx":
            if not DOCX_AVAILABLE:
                return ["WARNING: python-docx not installed. Skipping DOCX scan."]
            content = _read_docx(file_path)
        else:
            return [] # Unsupported format

        # 2. Analysis (Common for all text)
        if not content:
            return []

        signatures = SignatureLoader.get_prompt_injections()
        
        # Optimization: we check with chunks if the text is huge, 
        # but for PDF/Docx, the text usually fits into memory.
        # We use line-by-line/block-by-block verification for accuracy.
        
        # Split into lines for accurate search (and so as not to hang Regex on a 10MB line)
        lines = content.splitlines()
        for i, line in enumerate(lines):
            # Limit line length to prevent ReDoS
            if len(line) > 4096: 
                line = line[:4096]
            
            if is_match(line, signatures):
                for pattern in signatures:
                    if is_match(line, [pattern]):
                        threats.append(f"HIGH: Prompt Injection detected in {file_path.name} (approx line {i+1}): '{pattern}'")
                        return threats # Fail fast strategy

    except Exception as e:
        logger.warning(f"Failed to scan document {file_path}: {e}")
        threats.append(f"WARNING: Document Scan Error: {str(e)}")
        
    return threats


def _read_text(path: Path) -> str:
    """Reads standard text files with size limit."""
    # Limit 5MB to prevent DoS
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read(5 * 1024 * 1024)

def _read_pdf(path: Path) -> str:
    """Extracts text from PDF (Text Layer Only)."""
    text_content = []
    try:
        reader = pypdf.PdfReader(path)
        # Limit pages to prevent processing 1000-page books forever
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
    """Extracts text from DOCX."""
    text_content = []
    try:
        doc = docx.Document(path)
        # Limit paragraphs
        max_paras = min(len(doc.paragraphs), 2000)
        
        for i in range(max_paras):
            text_content.append(doc.paragraphs[i].text)
            
        return "\n".join(text_content)
    except Exception as e:
        logger.debug(f"DOCX parsing error: {e}")
        return ""
