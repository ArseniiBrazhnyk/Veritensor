import textwrap
import pytest
from typer.testing import CliRunner
from veritensor.cli.main import app
from unittest.mock import patch, MagicMock
from veritensor.core.streaming import AWS_AVAILABLE

runner = CliRunner()


def test_cli_scan_clean(clean_model_path):
    # 1. Running the scanner on a clean file
    result = runner.invoke(app, ["scan", str(clean_model_path)])
    
    # 2. Awaiting success (Exit Code 0)
    assert result.exit_code == 0
    assert "Scan Passed" in result.stdout

def test_cli_scan_infected(infected_pickle_path):
    # 1. Running on a virus
    result = runner.invoke(app, ["scan", str(infected_pickle_path)])
    
    # 2. We expect failure (Exit Code 1)
    assert result.exit_code == 1
    assert "BLOCKING DEPLOYMENT" in result.stdout
    assert "CRITICAL" in result.stdout

def test_cli_ignore_malware(infected_pickle_path):
    # Should pass with warning
    result = runner.invoke(app, ["scan", str(infected_pickle_path), "--ignore-malware"])
    assert result.exit_code == 0
    assert "MALWARE/INTEGRITY RISKS DETECTED (Ignored by user)" in result.stdout

def test_cli_force_deprecated(infected_pickle_path):
    # Should pass but maybe warn about deprecation
    result = runner.invoke(app, ["scan", str(infected_pickle_path), "--force"])
    assert result.exit_code == 0
    assert "RISKS DETECTED" in result.stdout

@patch("requests.get")
def test_cli_update(mock_get, tmp_path):
    """
    Tests the update command with a simulated GitHub response.
    """
    # 1. Mock server response
    mock_response = MagicMock()
    mock_response.status_code = 200
    
    # Using textwrap.dedent to ensure valid YAML formatting regardless of indentation
    mock_response.text = textwrap.dedent("""
    version: "2099.01.01"
    unsafe_globals:
      CRITICAL:
        os: "*"
    """).strip()
    
    mock_get.return_value = mock_response

    # 2. Mock user home directory to avoid polluting real system
    with patch("pathlib.Path.home", return_value=tmp_path):
        # Run command
        result = runner.invoke(app, ["update"])
        
        if result.exit_code != 0:
            print(f"\n[DEBUG] CLI Output:\n{result.stdout}")
        
        # Check success
        assert result.exit_code == 0
        assert "Successfully updated" in result.stdout
        
        # Verify file creation
        saved_file = tmp_path / ".veritensor" / "signatures.yaml"
        assert saved_file.exists()
        assert "2099.01.01" in saved_file.read_text()

@pytest.mark.skipif(not AWS_AVAILABLE, reason="AWS (boto3) not installed")
def test_s3_scan_flow():
    """
    Test scanning an S3 bucket URI.
    Skipped if boto3 is not installed.
    """
    result = runner.invoke(app, ["scan", "s3://bucket/model.pkl"])
    pass
