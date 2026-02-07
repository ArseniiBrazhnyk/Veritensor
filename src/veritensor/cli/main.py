# Copyright 2026 Veritensor Security Apache 2.0
# The Main CLI Entry Point.
# Orchestrates: Config -> Scan (Parallel) -> Verify -> Sign.

import sys
import typer
import logging
import json
import os
import datetime
import requests
import concurrent.futures
import multiprocessing
from pathlib import Path
from typing import Optional, List, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

# --- Internal Modules ---
from veritensor.core.config import ConfigLoader, VeritensorConfig
from veritensor.core.types import ScanResult
from veritensor.core.cache import HashCache
from veritensor.core.streaming import get_stream_for_path
from veritensor.engines.hashing.calculator import calculate_sha256
from veritensor.engines.hashing.readers import get_reader_for_file 
from veritensor.engines.static.pickle_engine import scan_pickle_stream
from veritensor.engines.static.keras_engine import scan_keras_file

# Robust import for rules
try:
    from veritensor.engines.static.rules import is_license_restricted, is_match
except ImportError:
    from veritensor.engines.static.rules import is_license_restricted
    def is_match(repo, allowed): return False

from veritensor.integrations.cosign import sign_container, is_cosign_available, generate_key_pair
from veritensor.integrations.huggingface import HuggingFaceClient
from veritensor.engines.content.injection import scan_document, TEXT_EXTENSIONS, DOC_EXTS
from veritensor.engines.static.notebook_engine import scan_notebook
from veritensor.engines.data.dataset_engine import scan_dataset
from veritensor.engines.static.dependency_engine import scan_dependencies # <--- NEW IMPORT
from veritensor.reporting.telemetry import send_report

# --- Reporting Modules ---
from veritensor.reporting.sarif import generate_sarif_report
from veritensor.reporting.sbom import generate_sbom

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("veritensor")
app = typer.Typer(help="Veritensor: AI Model Security Scanner & Gatekeeper")
console = Console()

# Extensions
PICKLE_EXTS = {".pt", ".pth", ".bin", ".pkl", ".ckpt", ".whl"}
KERAS_EXTS = {".h5", ".keras"}
NOTEBOOK_EXTS = {".ipynb"}
DATASET_EXTS = {".parquet", ".csv", ".jsonl"}
DEP_FILES = {"requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "Pipfile.lock"} 
ALL_DOC_EXTS = TEXT_EXTENSIONS.union(DOC_EXTS)

SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def check_severity(threats: List[str], threshold: str) -> bool:
    threshold_val = SEVERITY_LEVELS.get(threshold.upper(), 4)
    for threat in threats:
        parts = threat.split(":")
        if len(parts) > 0:
            level_str = parts[0].strip().upper()
            level_val = SEVERITY_LEVELS.get(level_str, 3) 
            if level_val >= threshold_val:
                return True
    return False

# --- WORKER FUNCTION (Must be at module level for multiprocessing) ---
def scan_worker(args: Tuple[str, VeritensorConfig, Optional[str], bool, bool, bool]) -> ScanResult:
    """
    Independent worker function that scans a single file.
    Args: (file_path_str, config, repo, ignore_license, full_scan_dataset, is_s3)
    """
    file_path_str, config, repo, ignore_license, full_scan_dataset, is_s3 = args
    
    # Robust Path Handling for S3 vs Local
    if is_s3:
        file_name = file_path_str.split("/")[-1]
        ext = os.path.splitext(file_name)[1].lower()
        file_path = None 
    else:
        file_path = Path(file_path_str)
        file_name = file_path.name
        ext = "".join(file_path.suffixes).lower()
        if not ext: ext = file_path.suffix.lower()
    
    filename_lower = file_name.lower()

    scan_res = ScanResult(file_path=file_path_str)
    scan_res.repo_id = repo 

    # --- A. Identity & Hashing ---
    if not is_s3 and file_path:
        try:
            file_hash = calculate_sha256(file_path)
            scan_res.file_hash = file_hash
            
            if repo:
                hf_client = HuggingFaceClient(token=config.hf_token)
                verification = hf_client.verify_file_hash(repo, file_name, file_hash)
                if verification == "VERIFIED":
                    scan_res.identity_verified = True
                elif verification == "MISMATCH":
                    file_size = file_path.stat().st_size
                    if file_size < 2048:
                        scan_res.add_threat(
                            f"CRITICAL: Hash mismatch! Likely Git LFS pointer ({file_size} b)."
                        )
                    else:
                        scan_res.add_threat(f"CRITICAL: Hash mismatch! File differs from '{repo}'")
        except Exception as e:
            scan_res.add_threat(f"CRITICAL: Hashing Error: {str(e)}")

    # --- B. Static Analysis ---
    try:
        # 1. Pickle / PyTorch
        if ext in PICKLE_EXTS:
            with get_stream_for_path(file_path_str) as f:
                threats = scan_pickle_stream(f, strict_mode=True)
                for t in threats: scan_res.add_threat(t)
        
        # 2. Keras
        elif ext in KERAS_EXTS:
            if is_s3:
                scan_res.add_threat("WARNING: S3 scanning not supported for Keras yet.")
            else:
                if file_path:
                    threats = scan_keras_file(file_path)
                    for t in threats: scan_res.add_threat(t)
        
        # 3. Documents (RAG)
        elif ext in ALL_DOC_EXTS or filename_lower == "dockerfile":
            if is_s3:
                 scan_res.add_threat("WARNING: S3 scanning not supported for Documents yet.")
            else:
                if file_path:
                    threats = scan_document(file_path)
                    for t in threats: scan_res.add_threat(t)

        # 4. Notebooks
        elif ext in NOTEBOOK_EXTS:
            if is_s3:
                 scan_res.add_threat("WARNING: S3 scanning not supported for Notebooks yet.")
            else:
                if file_path:
                    threats = scan_notebook(file_path)
                    for t in threats: scan_res.add_threat(t)

        # 5. Datasets
        elif ext in DATASET_EXTS:
            if is_s3:
                 scan_res.add_threat("WARNING: S3 scanning not supported for Datasets yet.")
            else:
                if file_path:
                    threats = scan_dataset(file_path, full_scan=full_scan_dataset)
                    for t in threats: scan_res.add_threat(t)
        
        # 6. Dependencies (Supply Chain) <--- NEW BLOCK
        elif file_name in DEP_FILES:
            if is_s3:
                 scan_res.add_threat("WARNING: S3 scanning not supported for Dependencies yet.")
            else:
                if file_path:
                    threats = scan_dependencies(file_path)
                    for t in threats: scan_res.add_threat(t)

    except Exception as e:
        scan_res.add_threat(f"CRITICAL: Engine Error: {str(e)}")

    # --- C. License Check (Local only) ---
    if not is_s3 and file_path:
        reader = get_reader_for_file(file_path)
        license_str = None
        
        if reader:
            file_info = reader.read_metadata(file_path)
            scan_res.file_format = file_info.get("format")
            if "error" in file_info:
                scan_res.add_threat(f"MEDIUM: Metadata parse error: {file_info['error']}")
            else:
                meta_dict = file_info.get("metadata", {})
                license_str = meta_dict.get("license", None)
                scan_res.detected_license = license_str

        is_whitelisted = repo and is_match(repo, config.allowed_models)
        
        if not is_whitelisted:
            if not license_str and reader:
                msg = "WARNING: License metadata not found."
                if config.fail_on_missing_license:
                    scan_res.add_threat(f"HIGH: {msg}")
                else:
                    scan_res.threats.append(f"INFO: {msg}")
            elif license_str and is_license_restricted(license_str, config.custom_restricted_licenses):
                scan_res.add_threat(f"HIGH: Restricted license detected: '{license_str}'")

    return scan_res


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to model file, directory, or S3 URL"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Hugging Face Repo ID"),
    image: Optional[str] = typer.Option(None, help="Docker image tag to sign"),
    
    ignore_license: bool = typer.Option(False, "--ignore-license", help="Do not fail on license violations"),
    ignore_malware: bool = typer.Option(False, "--ignore-malware", help="Do not fail on malware/policy violations"),
    full_scan: bool = typer.Option(False, "--full-scan", help="Scan entire dataset (slow). Default: first 10k rows."),
    
    jobs: int = typer.Option(None, "--jobs", "-j", help="Number of parallel jobs. Default: CPU count"),

    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
    sarif_output: bool = typer.Option(False, "--sarif", help="Output SARIF"),
    sbom_output: bool = typer.Option(False, "--sbom", help="Output CycloneDX SBOM"),

    report_to: Optional[str] = typer.Option(None, help="URL to send scan report (Enterprise)"),
    api_key: Optional[str] = typer.Option(None, envvar="VERITENSOR_API_KEY", help="API Key for reporting"),

    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed logs"),
):
    """
    Scans models/data for malware, secrets, and license compliance.
    """
    config = ConfigLoader.load()
    if verbose:
        logger.setLevel(logging.DEBUG)

    is_machine_output = json_output or sarif_output or sbom_output

    if not is_machine_output:
        console.print(Panel.fit(f"🛡️  [bold cyan]Veritensor Security Scanner[/bold cyan] v1.4.1", border_style="cyan"))

    # 1. Collect Files
    files_to_scan = []
    is_s3 = path.startswith("s3://")
    
    if is_s3:
        files_to_scan.append(path) 
    else:
        local_path = Path(path)
        if local_path.is_file():
            files_to_scan.append(local_path)
        elif local_path.is_dir():
            files_to_scan.extend([p for p in local_path.rglob("*") if p.is_file()])
        else:
            console.print(f"[bold red]Error:[/bold red] Path {path} not found.")
            raise typer.Exit(code=1)

    if not files_to_scan:
        console.print("[yellow]No files found to scan.[/yellow]")
        raise typer.Exit(code=0)

    # 2. Cache & Preparation
    hash_cache = HashCache()
    results: List[ScanResult] = []
    
    if jobs is None:
        try:
            jobs = multiprocessing.cpu_count()
        except NotImplementedError:
            jobs = 1
            
    if len(files_to_scan) == 1:
        jobs = 1

    tasks = []
    if not is_s3:
        for f in files_to_scan:
            tasks.append((str(f), config, repo, ignore_license, full_scan, False))
    else:
        tasks.append((path, config, repo, ignore_license, full_scan, True))

    # 3. Execution (Parallel) with ANTI-HANG protection
    if not is_machine_output:
        console.print(f"[dim]🚀 Starting scan with {jobs} workers on {len(tasks)} files...[/dim]")

    executor = None
    try:
        with Progress(
            SpinnerColumn(), 
            TextColumn("[progress.description]{task.description}"), 
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            transient=True, 
            disable=is_machine_output
        ) as progress:
            
            main_task = progress.add_task("Scanning...", total=len(tasks))
            
            executor = concurrent.futures.ProcessPoolExecutor(max_workers=jobs)
            
            future_to_file = {
                executor.submit(scan_worker, task_args): task_args[0] 
                for task_args in tasks
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_p = future_to_file[future]
                try:
                    res = future.result()
                    results.append(res)
                    
                    if res.file_hash and not is_s3:
                        hash_cache.set(Path(res.file_path), res.file_hash)
                        
                except Exception as exc:
                    err_res = ScanResult(file_path=file_p, status="FAIL")
                    err_res.add_threat(f"CRITICAL: Worker Crashed: {exc}")
                    results.append(err_res)
                
                progress.advance(main_task)

    finally:
        if executor:
            executor.shutdown(wait=True)
        hash_cache.close()

    # 4. Analysis & Reporting
    found_malware = False
    found_license_issue = False
    found_integrity_issue = False

    for res in results:
        if res.status == "FAIL":
            if check_severity(res.threats, config.fail_on_severity):
                for t in res.threats:
                    if "License" in t or "Restricted license" in t:
                        found_license_issue = True
                    elif "Hash mismatch" in t:
                        found_integrity_issue = True
                    else:
                        found_malware = True

    if sarif_output:
        print(generate_sarif_report(results))
    elif sbom_output:
        print(generate_sbom(results))
    elif json_output:
        results_dicts = [r.__dict__ for r in results]
        print(json.dumps(results_dicts, indent=2))
    else:
        _print_table(results)

    if report_to or config.report_url:
        if not is_machine_output:
            console.print(f"[dim]📡 Sending telemetry...[/dim]")
        send_report(results, config, override_url=report_to, override_key=api_key)

    # 5. Decision Logic
    exit_code = 0
    sign_status = "clean"
    block_reasons = []

    if found_malware or found_integrity_issue:
        if ignore_malware:
            if not is_machine_output:
                console.print("\n[bold yellow]⚠️  MALWARE/INTEGRITY RISKS DETECTED (Ignored by user)[/bold yellow]")
            sign_status = "forced_approval"
        else:
            block_reasons.append("Malware/Integrity")
            exit_code = 1

    if found_license_issue:
        if ignore_license:
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

    # 6. Signing
    if image:
        scan_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _perform_signing(image, sign_status, config, scan_timestamp, results)


def _print_table(results: List[ScanResult]):
    """
    Renders results in a smart table.
    Shows ALL threats without truncation.
    """
    table = Table(title="🛡️ Veritensor Scan Report", header_style="bold magenta")
    table.add_column("File", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Threats", style="white")

    for res in results:
        status_style = "green" if res.status == "PASS" else "bold red"
        
        # Threat Grouping Logic
        if not res.threats:
            display_threats = "[dim]None[/dim]"
        else:
            # Remove duplicates while preserving order
            unique_threats = list(dict.fromkeys(res.threats))
            
            display_threats = "\n".join(unique_threats)

        table.add_row(
            res.file_path.split("/")[-1], # Show only filename for cleanliness
            f"[{status_style}]{res.status}[/{status_style}]",
            display_threats
        )
    console.print(table)


def _perform_signing(image: str, status: str, config, timestamp: str, results: List[ScanResult]):
    console.print(f"\n🔐 [bold]Signing container:[/bold] {image}")
    key_path = config.private_key_path or os.environ.get("VERITENSOR_PRIVATE_KEY_PATH")
    if not key_path:
         console.print("[red]Skipping signing: No private key found.[/red]")
         return
    
    annotations = {
        "scanned_by": "veritensor",
        "status": status,
        "scan_date": timestamp
    }

    if results:
        primary = results[0]
        if primary.file_hash:
            annotations["ai.model.hash"] = primary.file_hash
        if primary.detected_license:
            annotations["ai.model.license"] = primary.detected_license
        if primary.repo_id:
            annotations["ai.model.source"] = primary.repo_id

    success = sign_container(image, key_path, annotations=annotations)
    
    if success:
        console.print(f"[green]✔ Signed with Smart Attestation.[/green]")
    else:
        console.print(f"[bold red]Signing Failed.[/bold red]")


@app.command()
def keygen(output_prefix: str = "veritensor"):
    """Generates a generic Cosign key pair."""
    console.print(f"[bold]Generating Cosign Key Pair ({output_prefix})...[/bold]")
    if not is_cosign_available():
        console.print("[bold red]Error:[/bold red] 'cosign' binary not found.")
        raise typer.Exit(code=1)
    if generate_key_pair(output_prefix):
        console.print(f"[green]✔ Keys generated: {output_prefix}.key / {output_prefix}.pub[/green]")
    else:
        console.print("[red]Key generation failed.[/red]")


@app.command()
def update():
    """Downloads the latest security signatures."""
    SIG_URL = "https://raw.githubusercontent.com/ArseniiBrazhnyk/Veritensor/main/src/veritensor/engines/static/signatures.yaml"
    target_dir = Path.home() / ".veritensor"
    target_file = target_dir / "signatures.yaml"
    console.print(f"⬇️  Checking for updates from [cyan]{SIG_URL}[/cyan]...")
    try:
        response = requests.get(SIG_URL, timeout=10)
        response.raise_for_status()
        import yaml
        data = yaml.safe_load(response.text)
        if "unsafe_globals" not in data: raise ValueError("Invalid signature format")
        target_dir.mkdir(parents=True, exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(response.text)
        console.print(f"[green]✅ Signatures updated![/green]")
    except Exception as e:
        console.print(f"[bold red]❌ Update failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def version():
    console.print("Veritensor v1.4.1 (Community Edition)")


@app.command()
def init():
    """Create default config."""
    config_content = """# Veritensor Configuration
fail_on_severity: CRITICAL
fail_on_missing_license: false
custom_restricted_licenses:
  - "cc-by-nc"
"""
    target_path = Path("veritensor.yaml")
    if target_path.exists():
        console.print("[yellow]veritensor.yaml already exists.[/yellow]")
    else:
        with open(target_path, "w") as f: f.write(config_content)
        console.print("[green]✔ Created default veritensor.yaml[/green]")

if __name__ == "__main__":
    app()
