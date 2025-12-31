from typer.testing import CliRunner
from veritensor.cli.main import app

runner = CliRunner()

def test_cli_scan_clean(clean_model_path):
    #1. Running the scanner on a clean file
    result = runner.invoke(app, [str(clean_model_path)])
    
    # 2. We expect success (Exit Code 0)
    assert result.exit_code == 0
    assert "Scan Passed" in result.stdout

def test_cli_scan_infected(infected_pickle_path):
    #1. Running on a virus
    result = runner.invoke(app, [str(infected_pickle_path)])
    
    # 2. We expect failure (Exit Code 1)
    assert result.exit_code == 1
    assert "BLOCKING DEPLOYMENT" in result.stdout
    assert "CRITICAL" in result.stdout

def test_cli_break_glass(infected_pickle_path):
    #1. Running on a virus, but with the --force flag
    result = runner.invoke(app, [str(infected_pickle_path), "--force"])
    
    # 2. We expect success (Exit Code 0), but with a warning
    assert result.exit_code == 0
    assert "Break-glass mode enabled" in result.stdout
