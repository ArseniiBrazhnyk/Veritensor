import pytest
import textwrap
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from veritensor.cli.main import app
from veritensor.core.streaming import AWS_AVAILABLE

runner = CliRunner()

def test_cli_scan_clean(tmp_path):
    """
    1. Test scanning a clean file.
    We create a dummy valid pickle file (empty dict).
    """
    f = tmp_path / "clean_model.pkl"
    # Bytecode for an empty dictionary {}
    f.write_bytes(b"\x80\x04\x95\x02\x00\x00\x00\x00\x00\x00\x00}\x94.") 

    result = runner.invoke(app, ["scan", str(f)])
    
    assert result.exit_code == 0
    assert "Scan Passed" in result.stdout

def test_cli_scan_infected(tmp_path):
    """
    2. Test scanning a 'broken' or malicious file.
    Writing garbage text to a .pkl will cause the engine to report a CRITICAL error/crash,
    which Veritensor treats as a blocking failure.
    """
    f = tmp_path / "infected.pkl"
    f.write_text("malware_signature_not_a_pickle")

    result = runner.invoke(app, ["scan", str(f)])
    
    # Expect failure because the engine failed to parse (CRITICAL threat)
    assert result.exit_code == 1
    assert "BLOCKING DEPLOYMENT" in result.stdout

def test_cli_ignore_malware(tmp_path):
    """
    3. Test the --ignore-malware flag (Replacement for --force).
    Even with a bad file, it should exit with code 0.
    """
    f = tmp_path / "risky_model.pkl"
    f.write_text("malware_content") 
    
    result = runner.invoke(app, ["scan", str(f), "--ignore-malware"])
    
    assert result.exit_code == 0
    assert "MALWARE/INTEGRITY RISKS DETECTED (Ignored by user)" in result.stdout

def test_cli_ignore_license(tmp_path):
    """
    4. Test the --ignore-license flag.
    """
    f = tmp_path / "model.pkl"
    f.write_bytes(b".")
    
    result = runner.invoke(app, ["scan", str(f), "--ignore-license"])
    assert result.exit_code == 0

@patch("requests.get")
def test_cli_update(mock_get, tmp_path):
    """
    5. Test the update command with a simulated GitHub response.
    """
    # 1. Mock server response
    mock_response = MagicMock()
    mock_response.status_code = 200
    
    # Mock valid YAML response
    mock_response.text = textwrap.dedent("""
    version: "2099.01.01"
    unsafe_globals:
      CRITICAL:
        os: "*"
    """).strip()
    
    mock_get.return_value = mock_response

    # 2. Mock user home directory to ensure we write to tmp_path, not real ~/.veritensor
    with patch("pathlib.Path.home", return_value=tmp_path):
        result = runner.invoke(app, ["update"])
        
        # Check success
        assert result.exit_code == 0
        # FIXED: Updated assertion to match main.py output ("✅ Signatures updated!")
        assert "Signatures updated!" in result.stdout
        
        # Verify file creation
        saved_file = tmp_path / ".veritensor" / "signatures.yaml"
        assert saved_file.exists()
        assert "2099.01.01" in saved_file.read_text()

@pytest.mark.skipif(not AWS_AVAILABLE, reason="AWS (boto3) not installed")
def test_s3_scan_flow():
    """
    Test scanning an S3 bucket URI.
    Skipped if boto3 is not installed to prevent crashes in CI.
    """
    # We just check if the CLI accepts the URL schema without crashing immediately
    # Real network call would fail without creds, so we expect exit_code 1 or handled error
    result = runner.invoke(app, ["scan", "s3://bucket/model.pkl"])
    
    # If no creds, it fails, but that proves the flow worked up to the engine.
    # We just ensure it didn't crash with a traceback.
    assert "Traceback" not in result.stdout
