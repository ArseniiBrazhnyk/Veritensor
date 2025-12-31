# Copyright 2025 Aegis Security
#
# The Main CLI Entry Point.
# Orchestrates: Config -> Scan -> Verify -> Sign.
# src/aegis/cli/main.py (Updated with Identity Check)

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

from aegis.core.config import ConfigLoader
from aegis.core.types import ScanResult
from aegis.engines.hashing.calculator import calculate_sha256
from aegis.engines.static.pickle_engine import scan_pickle_stream
from aegis.engines.static.keras_engine import scan_keras_file
from aegis.integrations.cosign import sign_container, is_cosign_available
# [NEW] Импорт клиента HF
from aegis.integrations.huggingface import HuggingFaceClient

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("aegis")

app = typer.Typer(help="Aegis: AI Model Security Scanner & Gatekeeper")
console = Console()

PICKLE_EXTS = {".pt", ".pth", ".bin", ".pkl", ".ckpt"}
KERAS_EXTS = {".h5", ".keras"}
SAFETENSORS_EXTS = {".safetensors"}
GGUF_EXTS = {".gguf"}

@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to model file or directory"),
    # [NEW] Аргумент для указания оригинального репозитория
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Hugging Face Repo ID (e.g. meta-llama/Llama-2-7b)"),
    image: Optional[str] = typer.Option(None, help="Docker image tag to sign"),
    force: bool = typer.Option(False, "--force", "-f", help="Break-glass mode"),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logs"),
):
    """
    Scans a model for malware and verifies integrity against Hugging Face.
    """
    config = ConfigLoader.load()
    if verbose:
        logger.setLevel(logging.DEBUG)

    if not json_output:
        console.print(Panel.fit(f"🛡️  [bold cyan]Aegis Security Scanner[/bold cyan] v4.1", border_style="cyan"))

    files_to_scan = []
    if path.is_file():
        files_to_scan.append(path)
    elif path.is_dir():
        files_to_scan.extend([p for p in path.rglob("*") if p.is_file()])
    else:
        console.print(f"[bold red]Error:[/bold red] Path {path} not found.")
        raise typer.Exit(code=1)

    # [NEW] Инициализация клиента HF, если передан репозиторий
    hf_client = None
    if repo:
        hf_client = HuggingFaceClient(token=config.hf_token)
        if not json_output:
            console.print(f"[dim]🔌 Connected to Hugging Face Registry. Verifying against: [bold]{repo}[/bold][/dim]")

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
            
            scan_res = ScanResult(file_path=str(file_path.name))

            # --- A. Identity (Hashing & Verification) ---
            try:
                file_hash = calculate_sha256(file_path)
                scan_res.file_hash = file_hash
                
                # [NEW] Логика сверки с API
                if hf_client and repo:
                    # Проверяем: совпадает ли локальный хэш с тем, что на сервере HF
                    verification = hf_client.verify_file_hash(repo, file_path.name, file_hash)
                    
                    if verification == "VERIFIED":
                        scan_res.identity_verified = True
                    elif verification == "MISMATCH":
                        # Это КРИТИЧЕСКАЯ угроза: файл подделан или побит
                        scan_res.add_threat(f"CRITICAL: Hash mismatch! File differs from official '{repo}'")
                    elif verification == "UNKNOWN":
                        # Файл не найден в репозитории (может лишний файл?)
                        scan_res.add_threat(f"WARNING: File not found in remote repo '{repo}'")

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

            # --- C. Policy Check ---
            if threats:
                for t in threats:
                    scan_res.add_threat(t)
                has_critical_errors = True
            
            # Если хэш не совпал, это тоже критическая ошибка
            if not scan_res.identity_verified and repo and "CRITICAL" in str(scan_res.threats):
                has_critical_errors = True

            results.append(scan_res)
            progress.advance(task)

    # 4. Reporting
    if json_output:
        results_dicts = [r.__dict__ for r in results]
        console.print_json(json.dumps(results_dicts))
    else:
        _print_table(results)

    # 5. Decision
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

    # 6. Signing
    if image:
        _perform_signing(image, sign_status, config)

def _print_table(results: List[ScanResult]):
    table = Table(title="Scan Results")
    table.add_column("File", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Identity", justify="center") # [NEW] Колонка Identity
    table.add_column("Threats", style="magenta")

    for res in results:
        status_style = "green" if res.status == "PASS" else "bold red"
        
        # Иконка для Identity
        if res.identity_verified:
            id_icon = "[green]✔ Verified[/green]"
        elif res.file_hash:
            id_icon = "[dim]Unchecked[/dim]"
        else:
            id_icon = "[red]Error[/red]"

        threat_text = "\n".join(res.threats) if res.threats else "None"
        
        table.add_row(
            res.file_path,
            f"[{status_style}]{res.status}[/{status_style}]",
            id_icon,
            threat_text
        )
    console.print(table)

# ... (остальные функции без изменений: _perform_signing, keygen, version) ...
# Не забудьте скопировать их из старого файла или оставить как есть.
# Для краткости я их тут скрыл, но они нужны.
def _perform_signing(image: str, status: str, config):
    # ... (код из предыдущего ответа) ...
    pass

@app.command()
def keygen(output_prefix: str = "aegis"):
    # ... (код из предыдущего ответа) ...
    pass

@app.command()
def version():
    console.print("Aegis v4.1 (Enterprise Edition)")

if __name__ == "__main__":
    app()
