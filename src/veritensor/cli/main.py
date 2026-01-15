# Copyright 2025 Veritensor Security
# The Main CLI Entry Point.
# Orchestrates: Config -> Scan -> Verify -> Sign.


import sys
import typer
import logging
import json
import os
import datetime
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
from veritensor.engines.hashing.calculator import calculate_sha256
from veritensor.engines.hashing.readers import get_reader_for_file 
from veritensor.engines.static.pickle_engine import scan_pickle_stream
from veritensor.engines.static.keras_engine import scan_keras_file
from veritensor.engines.static.rules import is_license_restricted, is_match
from veritensor.integrations.cosign import sign_container, is_cosign_available, generate_key_pair
from veritensor.integrations.huggingface import HuggingFaceClient

# --- Reporting Modules ---
from veritensor.reporting.sarif import generate_sarif_report
from veritensor.reporting.sbom import generate_sbom

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("veritensor")
app = typer.Typer(help="Veritensor: AI Model Security Scanner & Gatekeeper")
console = Console()

PICKLE_EXTS = {".pt", ".pth", ".bin", ".pkl", ".ckpt"}
KERAS_EXTS = {".h5", ".keras"}
SAFETENSORS_EXTS = {".safetensors"}
GGUF_EXTS = {".gguf"}

SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def check_severity(threats: List[str], threshold: str) -> bool:
    """Returns True if any threat meets or exceeds the threshold."""
    threshold_val = SEVERITY_LEVELS.get(threshold.upper(), 4)
    for threat in threats:
        parts = threat.split(":")
        if len(parts) > 0:
            level_str = parts[0].strip().upper()
            level_val = SEVERITY_LEVELS.get(level_str, 0)
            if level_val >= threshold_val:
                return True
    return False

@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to model file or directory"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Hugging Face Repo ID"),
    image: Optional[str] = typer.Option(None, help="Docker image tag to sign"),
    force: bool = typer.Option(False, "--force", "-f", help="Break-glass: Force approval"),
    # --- Output Formats ---
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
    sarif_output: bool = typer.Option(False, "--sarif", help="Output SARIF (GitHub Security)"),
    sbom_output: bool = typer.Option(False, "--sbom", help="Output CycloneDX SBOM"),
    # ----------------------
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed logs"),
):
    """
    Scans a model for malware, checks license compliance, verifies integrity against Hugging Face.
    """
    config = ConfigLoader.load()
    if verbose:
        logger.setLevel(logging.DEBUG)

    is_machine_output = json_output or sarif_output or sbom_output

    if not is_machine_output:
        console.print(Panel.fit(f"🛡️  [bold cyan]Veritensor Security Scanner[/bold cyan] v1.2.3", border_style="cyan"))

    files_to_scan = []
    if path.is_file():
        files_to_scan.append(path)
    elif path.is_dir():
        files_to_scan.extend([p for p in path.rglob("*") if p.is_file()])
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
    has_blocking_errors = False

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, disable=is_machine_output) as progress:
        task = progress.add_task(f"Scanning {len(files_to_scan)} files...", total=len(files_to_scan))

        for file_path in files_to_scan:
            ext = file_path.suffix.lower()
            progress.update(task, description=f"Analyzing {file_path.name}...")
            
            scan_res = ScanResult(file_path=str(file_path.name))

            # --- A. Identity ---
            try:
                cached_hash = hash_cache.get(file_path)
                if cached_hash:
                    file_hash = cached_hash
                else:
                    file_hash = calculate_sha256(file_path)
                    hash_cache.set(file_path, file_hash)
                
                scan_res.file_hash = file_hash
                
                if hf_client and repo:
                    verification = hf_client.verify_file_hash(repo, file_path.name, file_hash)
                    if verification == "VERIFIED":
                        scan_res.identity_verified = True
                    elif verification == "MISMATCH":
                        scan_res.add_threat(f"CRITICAL: Hash mismatch! File differs from official '{repo}'")
            except Exception as e:
                scan_res.add_threat(f"CRITICAL: Hashing Error: {str(e)}")

            # --- B. Static Analysis ---
            threats = []
            if ext in PICKLE_EXTS:
                try:
                    with open(file_path, "rb") as f:
                        content = f.read() 
                        threats = scan_pickle_stream(content, strict_mode=True)
                except Exception as e:
                    threats.append(f"CRITICAL: Scan Error: {str(e)}")
            elif ext in KERAS_EXTS:
                threats = scan_keras_file(file_path)
            
            if threats:
                for t in threats:
                    scan_res.add_threat(t)

            # --- C. License Check (HYBRID MODE) ---
            reader = get_reader_for_file(file_path)
            license_str = None
            
            # 1. Try to read from file metadata
            if reader:
                file_info = reader.read_metadata(file_path)
                if "error" in file_info:
                     scan_res.add_threat(f"MEDIUM: Metadata parse error: {file_info['error']}")
                else:
                    meta_dict = file_info.get("metadata", {})
                    license_str = meta_dict.get("license", None)

            # 2. Fallback: Fetch from API if not in file AND repo is provided
            # Only if identity check didn't fail (don't trust API license for mismatched file)
            hash_failed = any("Hash mismatch" in t for t in scan_res.threats)
            
            if not license_str and hf_client and repo and not hash_failed:
                if not is_machine_output:
                    # Optional: log that we are fetching from API
                    pass
                try:
                    license_str = hf_client.get_model_license(repo)
                except Exception:
                    pass
            
            # 3. Validate License
            is_whitelisted = repo and is_match(repo, config.allowed_models)
            
            if not is_whitelisted:
                if not license_str:
                    msg = "WARNING: License metadata not found (checked File & API)."
                    if config.fail_on_missing_license:
                        scan_res.add_threat(f"HIGH: {msg} (Policy: fail_on_missing)")
                    else:
                        scan_res.threats.append(f"INFO: {msg}")
                elif is_license_restricted(license_str, config.custom_restricted_licenses):
                    scan_res.add_threat(f"HIGH: Restricted license detected: '{license_str}'")

            # --- D. Policy Check ---
            if scan_res.status == "FAIL":
                if check_severity(scan_res.threats, config.fail_on_severity):
                    has_blocking_errors = True

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

    # --- Decision ---
    sign_status = "clean"
    if has_blocking_errors:
        if force:
            if not is_machine_output:
                console.print("\n[bold yellow]⚠️  RISKS DETECTED (Force Approved)[/bold yellow]")
            sign_status = "forced_approval"
        else:
            if not is_machine_output:
                console.print("\n[bold red]❌ BLOCKING DEPLOYMENT[/bold red]")
            raise typer.Exit(code=1)
    else:
        if not is_machine_output:
            console.print("\n[bold green]✅ Scan Passed. Model is clean & verified.[/bold green]")

    # --- Signing ---
    if image:
        scan_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _perform_signing(image, sign_status, config, scan_timestamp)


def _print_table(results: List[ScanResult]):
    table = Table(title="Scan Results")
    table.add_column("File", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Identity", justify="center")
    table.add_column("Threats / Details", style="magenta")

    for res in results:
        status_style = "green" if res.status == "PASS" else "bold red"
        if res.identity_verified:
            id_icon = "[green]✔ Verified[/green]"
        elif res.file_hash:
            id_icon = "[dim]Unchecked[/dim]"
        else:
            id_icon = "[red]Error[/red]"
        threat_text = "\n".join(res.threats) if res.threats else "None"
        table.add_row(res.file_path, f"[{status_style}]{res.status}[/{status_style}]", id_icon, threat_text)
    console.print(table)


def _perform_signing(image: str, status: str, config, timestamp: str):
    console.print(f"\n🔐 [bold]Signing container:[/bold] {image}")
    key_path = config.private_key_path or os.environ.get("VERITENSOR_PRIVATE_KEY_PATH")
    if not key_path:
         console.print("[red]Skipping signing: No private key found (set VERITENSOR_PRIVATE_KEY_PATH).[/red]")
         return
    
    annotations = {
        "scanned_by": "veritensor",
        "status": status,
        "scan_date": timestamp
    }
    
    success = sign_container(image_ref=image, key_path=key_path, annotations=annotations)
    
    if success:
        console.print(f"[green]✔ Signed successfully with status: {status}[/green]")
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
def version():
    """
    Show version info.
    """
    console.print("Veritensor v1.3.0 (Community Edition)")

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
