# Copyright 2025 Veritensor Security Apache 2.0
# The Main CLI Entry Point.
# Orchestrates: Config -> Scan -> Verify -> Sign.

import sys
import typer
import logging
import json
import os
import datetime
import requests
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# --- Internal Modules ---
from veritensor.core.config import ConfigLoader
from veritensor.core.types import ScanResult
from veritensor.core.cache import HashCache
from veritensor.core.streaming import get_stream_for_path
from veritensor.engines.hashing.calculator import calculate_sha256
from veritensor.engines.hashing.readers import get_reader_for_file 
from veritensor.engines.static.pickle_engine import scan_pickle_stream
from veritensor.engines.static.keras_engine import scan_keras_file
from veritensor.engines.static.rules import is_license_restricted, is_match
from veritensor.integrations.cosign import sign_container, is_cosign_available, generate_key_pair
from veritensor.integrations.huggingface import HuggingFaceClient
from veritensor.engines.content.injection import scan_text_file, TEXT_EXTENSIONS
from veritensor.engines.static.notebook_engine import scan_notebook

# --- Reporting Modules ---
from veritensor.reporting.sarif import generate_sarif_report
from veritensor.reporting.sbom import generate_sbom
from veritensor.reporting.telemetry import send_report 

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("veritensor")
app = typer.Typer(help="Veritensor: AI Model Security Scanner & Gatekeeper")
console = Console()

PICKLE_EXTS = {".pt", ".pth", ".bin", ".pkl", ".ckpt", ".whl"}
KERAS_EXTS = {".h5", ".keras"}
SAFETENSORS_EXTS = {".safetensors"}
GGUF_EXTS = {".gguf"}
NOTEBOOK_EXTS = {".ipynb"}

SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def check_severity(threats: List[str], threshold: str) -> bool:
    """
    Returns True if any threat meets or exceeds the threshold.
    Fail-safe: If format is unknown, treats it as HIGH.
    """
    threshold_val = SEVERITY_LEVELS.get(threshold.upper(), 4) # Default to CRITICAL if config is wrong
    
    for threat in threats:
        parts = threat.split(":", 1) # Split only on first colon
        level_val = 3 # Default to HIGH (3) if parsing fails (Fail Safe logic)
        
        if len(parts) > 1:
            level_str = parts[0].strip().upper()
            if level_str in SEVERITY_LEVELS:
                level_val = SEVERITY_LEVELS[level_str]
        
        if level_val >= threshold_val:
            return True
    return False

@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to model file, directory, or S3 URL (s3://...)"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Hugging Face Repo ID"),
    image: Optional[str] = typer.Option(None, help="Docker image tag to sign"),
    
    # Granular Flags
    ignore_license: bool = typer.Option(False, "--ignore-license", help="Do not fail on license violations"),
    ignore_malware: bool = typer.Option(False, "--ignore-malware", help="Do not fail on malware/policy violations"),
    
    # Deprecated Force flag
    force: bool = typer.Option(False, "--force", "-f", hidden=True, help="Deprecated. Use --ignore-license"),

    # --- Output Formats ---
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
    sarif_output: bool = typer.Option(False, "--sarif", help="Output SARIF (GitHub Security)"),
    sbom_output: bool = typer.Option(False, "--sbom", help="Output CycloneDX SBOM"),

    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed logs"),

    report_to: Optional[str] = typer.Option(None, help="URL to send scan report (Enterprise feature)"),
    api_key: Optional[str] = typer.Option(None, envvar="VERITENSOR_API_KEY", help="API Key for reporting"),
):
    """
    Scans a model for malware, checks license compliance, verifies integrity against Hugging Face.
    """
    config = ConfigLoader.load()
    if verbose:
        logger.setLevel(logging.DEBUG)

    is_machine_output = json_output or sarif_output or sbom_output

    if not is_machine_output:
        console.print(Panel.fit(f"🛡️  [bold cyan]Veritensor Security Scanner[/bold cyan] v1.4.0", border_style="cyan"))

    # Handle S3 or Local Path
    files_to_scan = []
    if path.startswith("s3://"):
        # For S3, we treat the path as a single file for MVP
        files_to_scan.append(Path(path)) 
    else:
        local_path = Path(path)
        if local_path.is_file():
            files_to_scan.append(local_path)
        elif local_path.is_dir():
            files_to_scan.extend([p for p in local_path.rglob("*") if p.is_file()])
        else:
            console.print(f"[bold red]Error:[/bold red] Path {path} not found.")
            raise typer.Exit(code=1)

    hf_client = None
    if repo:
        hf_client = HuggingFaceClient(token=config.hf_token)
        if not is_machine_output:
            console.print(f"[dim]🔌 Connected to Hugging Face Registry. Verifying against: [bold]{repo}[/bold][/dim]")

    hash_cache = HashCache()
    results: List[ScanResult] = []
    
    # Track specific failure types for final decision
    found_malware = False
    found_license_issue = False
    found_integrity_issue = False

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, disable=is_machine_output) as progress:
        task = progress.add_task(f"Scanning {len(files_to_scan)} files...", total=len(files_to_scan))

        for file_path in files_to_scan:
            # Convert to string for processing, keep Path object for local file ops if needed
            file_path_str = str(file_path)
            file_name = file_path.name
            filename_lower = file_name.lower() # Checking Dockerfile
            ext = "".join(file_path.suffixes).lower() # Handle .tar.gz etc if needed, usually just .suffix
            if not ext: ext = file_path.suffix.lower()

            progress.update(task, description=f"Analyzing {file_name}...")
            
            scan_res = ScanResult(file_path=file_path_str)
            scan_res.repo_id = repo 

            # --- A. Identity ---
            # Skip hashing for S3 in MVP unless we stream it all (costly)
            # Only hash local files
            if not file_path_str.startswith("s3://"):
                try:
                    cached_hash = hash_cache.get(file_path)
                    if cached_hash:
                        file_hash = cached_hash
                    else:
                        file_hash = calculate_sha256(file_path)
                        hash_cache.set(file_path, file_hash)
                    
                    scan_res.file_hash = file_hash
                    
                    if hf_client and repo:
                        verification = hf_client.verify_file_hash(repo, file_name, file_hash)
                        if verification == "VERIFIED":
                            scan_res.identity_verified = True
                        elif verification == "MISMATCH":
                            # Check for LFS pointer confusion
                            # FIX: Fixed typo file_path_ -> file_path
                            file_size = file_path.stat().st_size
                            if file_size < 2048:
                                scan_res.add_threat(
                                    f"CRITICAL: Hash mismatch! Likely a Git LFS pointer ({file_size} bytes). "
                                    f"Run 'git lfs pull' or use 'huggingface-cli download'."
                                )
                            else:
                                scan_res.add_threat(f"CRITICAL: Hash mismatch! File differs from official '{repo}'")
                except Exception as e:
                    scan_res.add_threat(f"CRITICAL: Hashing Error: {str(e)}")

            # --- B. Static Analysis ---
            # 1. Pickle / PyTorch (Supports S3 via streaming)
            if ext in PICKLE_EXTS:
                try:
                    # FIX: Stream processing to avoid OOM on large files
                    with get_stream_for_path(file_path_str) as f:
                        # We pass the stream directly. The engine handles reading.
                        threats = scan_pickle_stream(f, strict_mode=True)
                except Exception as e:
                    threats = [f"CRITICAL: Scan Error: {str(e)}"]
                    scan_res.add_threat(threats[0])
                else:
                    if threats:
                        for t in threats:
                            scan_res.add_threat(t)
            
            # 2. Keras / H5 (Local only for now)
            elif ext in KERAS_EXTS:
                if file_path_str.startswith("s3://"):
                    scan_res.add_threat("WARNING: S3 scanning not supported for Keras yet.")
                else:
                    threats = scan_keras_file(file_path)
                    for t in threats: scan_res.add_threat(t)
            
            # 3. RAG / Text Files (New)
            elif ext in TEXT_EXTENSIONS or filename_lower == "dockerfile":
                if file_path_str.startswith("s3://"):
                     scan_res.add_threat("WARNING: S3 scanning not supported for Text files yet.")
                else:
                    try:
                        threats = scan_text_file(file_path)
                        for t in threats: scan_res.add_threat(t)
                    except Exception as e:
                        scan_res.add_threat(f"WARNING: RAG Scan Error: {str(e)}")
            # 4. Jupyter Notebooks
            elif ext in NOTEBOOK_EXTS:
                if file_path_str.startswith("s3://"):
                     scan_res.add_threat("WARNING: S3 scanning not supported for Notebooks yet.")
                else:
                    # Passing the Path object
                    threats = scan_notebook(file_path)
                    for t in threats: scan_res.add_threat(t)
                        
            # --- C. License Check ---
            # Only for local files
            if not file_path_str.startswith("s3://"):
                reader = get_reader_for_file(file_path)
                license_str = None
                
                # 1. Try file metadata
                if reader:
                    file_info = reader.read_metadata(file_path)
                    scan_res.file_format = file_info.get("format")
                    
                    if "error" in file_info:
                        scan_res.add_threat(f"MEDIUM: Metadata parse error: {file_info['error']}")
                    else:
                        meta_dict = file_info.get("metadata", {})
                        license_str = meta_dict.get("license", None)
                        scan_res.detected_license = license_str

                # 2. Fallback to API
                hash_failed = any("Hash mismatch" in t for t in scan_res.threats)
                if not license_str and hf_client and repo and not hash_failed:
                    try:
                        license_str = hf_client.get_model_license(repo)
                    except Exception:
                        pass
                
                # 3. Validate
                is_whitelisted = repo and is_match(repo, config.allowed_models)
                
                if not is_whitelisted:
                    if not license_str:
                        # Only warn if it's a model format that SHOULD have metadata
                        if reader:
                            msg = "WARNING: License metadata not found."
                            if config.fail_on_missing_license:
                                scan_res.add_threat(f"HIGH: {msg} (Policy: fail_on_missing)")
                            else:
                                scan_res.threats.append(f"INFO: {msg}")
                    elif is_license_restricted(license_str, config.custom_restricted_licenses):
                        scan_res.add_threat(f"HIGH: Restricted license detected: '{license_str}'")

            # --- D. Policy Check & Categorization ---
            if scan_res.status == "FAIL":
                if check_severity(scan_res.threats, config.fail_on_severity):
                    for t in scan_res.threats:
                        if "License" in t or "Restricted license" in t:
                            found_license_issue = True
                        elif "Hash mismatch" in t:
                            found_integrity_issue = True
                        else:
                            found_malware = True

            results.append(scan_res)
            progress.advance(task)

    # --- Reporting ---
    if sarif_output:
        print(generate_sarif_report(results))
    elif sbom_output:
        print(generate_sbom(results))
    elif json_output:
        results_dicts = [r.__dict__ for r in results]
        print(json.dumps(results_dicts, indent=2))
    else:
        _print_table(results)

    # --- Telemetry ---
    # Send the report regardless of whether it was scanned or dropped.
    if report_to or config.report_url:
        if not is_machine_output:
            console.print(f"[dim]📡 Sending telemetry...[/dim]")
        
        send_report(results, config, override_url=report_to, override_key=api_key)
    
    # --- Decision Logic ---
    exit_code = 0
    sign_status = "clean"
    block_reasons = []

    if found_malware or found_integrity_issue:
        if ignore_malware or force:
            if not is_machine_output:
                console.print("\n[bold yellow]⚠️  MALWARE/INTEGRITY RISKS DETECTED (Ignored by user)[/bold yellow]")
            sign_status = "forced_approval"
        else:
            block_reasons.append("Malware/Integrity")
            exit_code = 1

    if found_license_issue:
        if ignore_license or force:
            if not is_machine_output:
                console.print("\n[bold yellow]⚠️  LICENSE RISKS DETECTED (Ignored by user)[/bold yellow]")
            if sign_status == "clean": sign_status = "forced_approval"
        else:
            block_reasons.append("License")
            exit_code = 1

    if exit_code != 0:
        if not is_machine_output:
            console.print(f"\n[bold red]❌ BLOCKING DEPLOYMENT due to: {', '.join(block_reasons)}[/bold red]")
        raise typer.Exit(code=1)
    else:
        if not is_machine_output:
            console.print("\n[bold green]✅ Scan Passed.[/bold green]")

    # --- Signing (Smart Attestation) ---
    if image:
        
        scan_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _perform_signing(image, sign_status, config, scan_timestamp, results)


def _print_table(results: List[ScanResult]):
    table = Table(title="Scan Results")
    table.add_column("File", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("License", style="blue") 
    table.add_column("Threats", style="magenta")

    for res in results:
        status_style = "green" if res.status == "PASS" else "bold red"
        lic = res.detected_license or "Unknown"
        threats = "\n".join(res.threats) if res.threats else "None"
        table.add_row(res.file_path, f"[{status_style}]{res.status}[/{status_style}]", lic, threats)
    console.print(table)


def _perform_signing(image: str, status: str, config, timestamp: str, results: List[ScanResult]):
    """
    Signs with extended AI metadata (Smart Attestation).
    """
    console.print(f"\n🔐 [bold]Signing container:[/bold] {image}")
    key_path = config.private_key_path or os.environ.get("VERITENSOR_PRIVATE_KEY_PATH")
    if not key_path:
         console.print("[red]Skipping signing: No private key found (set VERITENSOR_PRIVATE_KEY_PATH).[/red]")
         return
    
    # Base annotations
    annotations = {
        "scanned_by": "veritensor",
        "status": status,
        "scan_date": timestamp
    }

    # Smart Attestation Logic
    # Extract metadata from the first valid result to embed in signature
    if results:
        primary = results[0]
        if primary.file_hash:
            annotations["ai.model.hash"] = primary.file_hash
        if primary.detected_license:
            annotations["ai.model.license"] = primary.detected_license
        if primary.repo_id:
            annotations["ai.model.source"] = primary.repo_id
        if hasattr(primary, 'file_format') and primary.file_format:
            annotations["ai.model.format"] = primary.file_format

    success = sign_container(image, key_path, annotations=annotations)
    
    if success:
        console.print(f"[green]✔ Signed with Smart Attestation.[/green]")
        if "ai.model.license" in annotations:
             console.print(f"[dim]   Metadata: License={annotations['ai.model.license']}[/dim]")
    else:
        console.print(f"[bold red]Signing Failed.[/bold red]")


@app.command()
def keygen(output_prefix: str = "veritensor"):
    """
    Generates a generic Cosign key pair for signing.
    """
    console.print(f"[bold]Generating Cosign Key Pair ({output_prefix})...[/bold]")
    if not is_cosign_available():
        console.print("[bold red]Error:[/bold red] 'cosign' binary not found in PATH.")
        raise typer.Exit(code=1)
    if generate_key_pair(output_prefix):
        console.print(f"[green]✔ Keys generated: {output_prefix}.key / {output_prefix}.pub[/green]")
    else:
        console.print("[red]Key generation failed.[/red]")

@app.command()
def update():
    """
    Downloads the latest security signatures from the official repository.
    """
    # Replace with your actual repo URL
    SIG_URL = "https://raw.githubusercontent.com/ArseniiBrazhnyk/Veritensor/main/src/veritensor/engines/static/signatures.yaml"
    
    target_dir = Path.home() / ".veritensor"
    target_file = target_dir / "signatures.yaml"
    
    console.print(f"⬇️  Checking for updates from [cyan]{SIG_URL}[/cyan]...")
    
    try:
        response = requests.get(SIG_URL, timeout=10)
        response.raise_for_status()
        
        # Validate YAML
        import yaml
        data = yaml.safe_load(response.text)
        if "unsafe_globals" not in data:
            raise ValueError("Invalid signature file format")
            
        version = data.get("version", "unknown")
        
        target_dir.mkdir(parents=True, exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(response.text)
            
        console.print(f"[green]✅ Successfully updated signatures to version {version}![/green]")
        console.print(f"[dim]Saved to: {target_file}[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]❌ Update failed:[/bold red] {e}")
        raise typer.Exit(code=1)

@app.command()
def version():
    """
    Show version info.
    """
    console.print("Veritensor v1.4.0 (Community Edition)")

@app.command()
def init():
    """
    Create a default configuration file (veritensor.yaml).
    """
    config_content = """# Veritensor Configuration

# Minimum severity to fail the build (CRITICAL, HIGH, MEDIUM, LOW)
fail_on_severity: CRITICAL

# License Policy
fail_on_missing_license: false
custom_restricted_licenses:
  - "cc-by-nc"
  - "agpl"
  - "research-only"

# Allow specific modules (Allowlist)
allowed_modules:
  # - "my_company.internal_layer"
  # - "sklearn.tree"

# Whitelist specific models (skip license checks)
allowed_models:
  # - "meta-llama/Meta-Llama-3-70B-Instruct"
  # - "regex:^google-bert/.*"
"""
    target_path = Path("veritensor.yaml")
    if target_path.exists():
        console.print("[yellow]veritensor.yaml already exists. Skipping.[/yellow]")
    else:
        with open(target_path, "w") as f:
            f.write(config_content)
        console.print("[green]✔ Created default veritensor.yaml[/green]")

if __name__ == "__main__":
    app()
