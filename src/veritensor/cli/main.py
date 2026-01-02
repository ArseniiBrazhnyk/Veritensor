# Copyright 2025 Veritensor Security
#
# The Main CLI Entry Point.
# Orchestrates: Config -> Scan -> Verify -> Sign.


import sys
import typer
import logging
import json
import os
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
from veritensor.engines.static.rules import is_license_restricted 
from veritensor.integrations.cosign import sign_container, is_cosign_available, generate_key_pair
from veritensor.integrations.huggingface import HuggingFaceClient


# ... (logging, app, console, extensions setup)
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("veritensor")
app = typer.Typer(help="Veritensor: AI Model Security Scanner & Gatekeeper")
console = Console()
PICKLE_EXTS = {".pt", ".pth", ".bin", ".pkl", ".ckpt"}
KERAS_EXTS = {".h5", ".keras"}
SAFETENSORS_EXTS = {".safetensors"}
GGUF_EXTS = {".gguf"}


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to model file or directory"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Hugging Face Repo ID (e.g. meta-llama/Llama-2-7b)"),
    image: Optional[str] = typer.Option(None, help="Docker image tag to sign (e.g. myrepo/model:v1)"),
    force: bool = typer.Option(False, "--force", "-f", help="Break-glass: Force approval even if risks found"),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed logs"),
):
    config = ConfigLoader.load()
    if verbose:
        logger.setLevel(logging.DEBUG)

    if not json_output:
        console.print(Panel.fit(f"🛡️  [bold cyan]Veritensor Security Scanner[/bold cyan] v1.0", border_style="cyan"))

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
        if not json_output:
            console.print(f"[dim]🔌 Connected to Hugging Face Registry. Verifying against: [bold]{repo}[/bold][/dim]")

    hash_cache = HashCache()
    results: List[ScanResult] = []
    has_critical_errors = False

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, disable=json_output) as progress:
        task = progress.add_task(f"Scanning {len(files_to_scan)} files...", total=len(files_to_scan))

        for file_path in files_to_scan:
            ext = file_path.suffix.lower()
            progress.update(task, description=f"Analyzing {file_path.name}...")
            
            scan_res = ScanResult(file_path=str(file_path.name))

            # --- A. Identity (Hashing & Verification) ---
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
                scan_res.add_threat(f"Hashing Error: {str(e)}")

            # --- B. Static Analysis ---
            threats = []
            if ext in PICKLE_EXTS:
                try:
                    with open(file_path, "rb") as f:
                        content = f.read() 
                        threats = scan_pickle_stream(content, strict_mode=True)
                except Exception as e:
                    threats.append(f"Scan Error: {str(e)}")
            elif ext in KERAS_EXTS:
                threats = scan_keras_file(file_path)
            
            if threats:
                for t in threats:
                    scan_res.add_threat(t)

            # --- C. License Check ---
             reader = get_reader_for_file(file_path)
            if reader:
                metadata = reader.read_metadata(file_path)
                license_str = metadata.get("license", None)
                
                #  Whitelist check
                # If the repository is on the whitelist, skip the license check
                is_whitelisted = repo and (repo in config.allowed_models)
                
                if not is_whitelisted:
                    # Checking for lack of a license
                    if not license_str:
                        msg = "WARNING: License metadata not found."
                        if config.fail_on_missing_license:
                            scan_res.add_threat(f"HIGH: {msg} (Policy: fail_on_missing)")
                        else:
                            # Just add it to the info without changing the status to FAIL.
                            scan_res.threats.append(f"INFO: {msg}")
                    
                    # Check for a prohibited license
                    elif is_license_restricted(license_str, config.custom_restricted_licenses):
                        scan_res.add_threat(f"HIGH: Restricted license detected: '{license_str}'")

            # --- D. Policy Check ---
            if scan_res.status == "FAIL":
                if any("CRITICAL" in t for t in scan_res.threats):
                    has_critical_errors = True
                # Можно добавить проверку на HIGH, если fail_on_severity = "HIGH"
                elif config.fail_on_severity == "HIGH" and any("HIGH" in t for t in scan_res.threats):
                    has_critical_errors = True

            results.append(scan_res)
            progress.advance(task)

    # ... (Reporting, Decision, Signing - без изменений)
    if json_output:
        results_dicts = [r.__dict__ for r in results]
        console.print_json(json.dumps(results_dicts))
    else:
        _print_table(results)

    sign_status = "clean"
    if has_critical_errors:
        if force:
            if not json_output:
                console.print("\n[bold yellow]⚠️  RISKS DETECTED (Force Approved)[/bold yellow]")
            sign_status = "forced_approval"
        else:
            if not json_output:
                console.print("\n[bold red]❌ BLOCKING DEPLOYMENT[/bold red]")
            raise typer.Exit(code=1)
    else:
        if not json_output:
            console.print("\n[bold green]✅ Scan Passed. Model is clean & verified.[/bold green]")

    if image:
        _perform_signing(image, sign_status, config)

# (all other functions _print_table, _perform_signing, keygen, version are unchanged)
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

def _perform_signing(image: str, status: str, config):
    console.print(f"\n🔐 [bold]Signing container:[/bold] {image}")
    key_path = config.private_key_path or os.environ.get("VERITENSOR_PRIVATE_KEY_PATH")
    if not key_path:
         console.print("[red]Skipping signing: No private key found (set VERITENSOR_PRIVATE_KEY_PATH).[/red]")
         return
    success = sign_container(image_ref=image, key_path=key_path, annotations={"scanned_by": "veritensor", "status": status})
    if success:
        console.print(f"[green]✔ Signed successfully with status: {status}[/green]")
    else:
        console.print(f"[bold red]Signing Failed.[/bold red]")

@app.command()
def keygen(output_prefix: str = "veritensor"):
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
    console.print("Veritensor v1.0 (Community Edition)")

if __name__ == "__main__":
    app()
