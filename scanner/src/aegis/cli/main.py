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
from veritensor.core.types import ScanResult, Severity
from veritensor.core.cache import HashCache
from veritensor.engines.hashing.calculator import calculate_sha256
from veritensor.engines.static.pickle_engine import scan_pickle_stream
from veritensor.engines.static.keras_engine import scan_keras_file
from veritensor.integrations.cosign import sign_container, is_cosign_available, generate_key_pair
from veritensor.integrations.huggingface import HuggingFaceClient

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("veritensor")

# Setup Typer & Rich
app = typer.Typer(help="Veritensor: AI Model Security Scanner & Gatekeeper")
console = Console()

# Supported Extensions
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
    """
    Scans a model for malware, verifies integrity against Hugging Face, and optionally signs the container.
    """
    # 1. Load Configuration
    config = ConfigLoader.load()
    if verbose:
        logger.setLevel(logging.DEBUG)
        console.print(f"[dim]Loaded config from {path}[/dim]")

    if not json_output:
        console.print(Panel.fit(f"🛡️  [bold cyan]Veritensor Security Scanner[/bold cyan] v4.1", border_style="cyan"))

    # 2. Collect Files
    files_to_scan = []
    if path.is_file():
        files_to_scan.append(path)
    elif path.is_dir():
        files_to_scan.extend([p for p in path.rglob("*") if p.is_file()])
    else:
        console.print(f"[bold red]Error:[/bold red] Path {path} not found.")
        raise typer.Exit(code=1)

    # 3. Initialize Clients & Cache
    hf_client = None
    if repo:
        hf_client = HuggingFaceClient(token=config.hf_token)
        if not json_output:
            console.print(f"[dim]🔌 Connected to Hugging Face Registry. Verifying against: [bold]{repo}[/bold][/dim]")

    hash_cache = HashCache()

    # 4. Execution Loop
    results: List[ScanResult] = []
    has_critical_errors = False

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        disable=json_output
    ) as progress:
        
        task = progress.add_task(f"Scanning {len(files_to_scan)} files...", total=len(files_to_scan))

        for file_path in files_to_scan:
            ext = file_path.suffix.lower()
            progress.update(task, description=f"Analyzing {file_path.name}...")
            
            # Initialize Result Object
            scan_res = ScanResult(file_path=str(file_path.name))

            # --- A. Identity (Hashing & Verification) ---
            try:
                # Check local cache first to speed up re-scans
                cached_hash = hash_cache.get(file_path)
                if cached_hash:
                    file_hash = cached_hash
                    if verbose:
                        logger.debug(f"Using cached hash for {file_path.name}")
                else:
                    # Calculate SHA256 (handles LFS pointers automatically)
                    file_hash = calculate_sha256(file_path)
                    hash_cache.set(file_path, file_hash)
                
                scan_res.file_hash = file_hash
                
                # Verify against Hugging Face API if repo is provided
                if hf_client and repo:
                    verification = hf_client.verify_file_hash(repo, file_path.name, file_hash)
                    
                    if verification == "VERIFIED":
                        scan_res.identity_verified = True
                    elif verification == "MISMATCH":
                        scan_res.add_threat(f"CRITICAL: Hash mismatch! File differs from official '{repo}'")
                    elif verification == "UNKNOWN":
                        scan_res.add_threat(f"WARNING: File not found in remote repo '{repo}'")

            except Exception as e:
                scan_res.add_threat(f"Hashing Error: {str(e)}")

            # --- B. Static Analysis ---
            threats = []
            
            # 1. Pickle / PyTorch
            if ext in PICKLE_EXTS:
                try:
                    with open(file_path, "rb") as f:
                        # For MVP simplicity, we read the raw stream.
                        # In production, use readers.py to extract pickle from zip if needed.
                        content = f.read() 
                        threats = scan_pickle_stream(content, strict_mode=True)
                except Exception as e:
                    threats.append(f"Scan Error: {str(e)}")

            # 2. Keras / H5
            elif ext in KERAS_EXTS:
                threats = scan_keras_file(file_path)

            # 3. Safetensors / GGUF (Generally Safe, check metadata)
            elif ext in SAFETENSORS_EXTS or ext in GGUF_EXTS:
                # Future: Check for license violations in metadata via readers.py
                pass

            # --- C. Policy Check ---
            if threats:
                for t in threats:
                    scan_res.add_threat(t)
                has_critical_errors = True
            
            # If identity check failed with mismatch, it is critical
            if not scan_res.identity_verified and repo:
                # Check if threats contain the CRITICAL mismatch message
                if any("CRITICAL" in t for t in scan_res.threats):
                    has_critical_errors = True

            results.append(scan_res)
            progress.advance(task)

    # 5. Reporting
    if json_output:
        # Serialize objects to dicts for JSON output
        results_dicts = [r.__dict__ for r in results]
        console.print_json(json.dumps(results_dicts))
    else:
        _print_table(results)

    # 6. Decision & Action
    sign_status = "clean"
    
    if has_critical_errors:
        if force:
            if not json_output:
                console.print("\n[bold yellow]⚠️  CRITICAL RISKS DETECTED[/bold yellow]")
                console.print(f"[yellow]Break-glass mode enabled (--force). Proceeding with caution.[/yellow]")
            # Add annotation to signature indicating forced approval
            sign_status = "forced_approval"
        else:
            if not json_output:
                console.print("\n[bold red]❌ BLOCKING DEPLOYMENT[/bold red]")
                console.print("Critical threats detected. Use --force to override if authorized.")
            raise typer.Exit(code=1)
    else:
        if not json_output:
            console.print("\n[bold green]✅ Scan Passed. Model is clean.[/bold green]")

    # 7. Signing (Sprint 4)
    if image:
        _perform_signing(image, sign_status, config)


def _print_table(results: List[ScanResult]):
    """Renders a pretty table of results using Rich."""
    table = Table(title="Scan Results")
    table.add_column("File", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Identity", justify="center")
    table.add_column("Threats / Details", style="magenta")
    table.add_column("SHA256 (Short)", style="dim")

    for res in results:
        status_style = "green" if res.status == "PASS" else "bold red"
        threat_text = "\n".join(res.threats) if res.threats else "None"
        short_hash = res.file_hash[:8] + "..." if res.file_hash else "N/A"
        
        # Identity Icon
        if res.identity_verified:
            id_icon = "[green]✔ Verified[/green]"
        elif res.file_hash:
            id_icon = "[dim]Unchecked[/dim]"
        else:
            id_icon = "[red]Error[/red]"

        table.add_row(
            res.file_path,
            f"[{status_style}]{res.status}[/{status_style}]",
            id_icon,
            threat_text,
            short_hash
        )
    console.print(table)


def _perform_signing(image: str, status: str, config):
    """
    Wrapper for Cosign integration to sign the container image.
    """
    console.print(f"\n🔐 [bold]Signing container:[/bold] {image}")
    
    # Determine key path (Config -> Env -> Default)
    key_path = config.private_key_path
    if not key_path and "VERITENSOR_PRIVATE_KEY_PATH" in os.environ:
        key_path = os.environ["VERITENSOR_PRIVATE_KEY_PATH"]
    
    if not key_path:
         console.print("[red]Skipping signing: No private key found (set VERITENSOR_PRIVATE_KEY_PATH).[/red]")
         return

    success = sign_container(
        image_ref=image, 
        key_path=key_path, 
        annotations={"scanned_by": "veritensor", "status": status}
    )

    if success:
        console.print(f"[green]✔ Signed successfully with status: {status}[/green]")
        console.print(f"[dim]Artifact pushed to OCI registry.[/dim]")
    else:
        console.print(f"[bold red]Signing Failed.[/bold red] Check logs for details.")
        # We don't fail the build if signing fails in MVP, unless strict mode is added later


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
        console.print(f"Set [cyan]VERITENSOR_PRIVATE_KEY_PATH={output_prefix}.key[/cyan] to use them.")
    else:
        console.print("[red]Key generation failed.[/red]")


@app.command()
def version():
    """Show version info."""
    console.print("Veritensor v4.1 (Enterprise Edition)")


if __name__ == "__main__":
    app()
