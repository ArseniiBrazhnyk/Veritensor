import pytest
import textwrap
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from veritensor.cli.main import app
from veritensor.core.streaming import AWS_AVAILABLE

runner = CliRunner()

# --- Helper Functions for File Creation ---

def create_clean_pickle(path):
    """
    Creates a safe pickle file containing an empty dictionary.
    Protocol 4, empty dict: {}
    """
    path.write_bytes(b"\x80\x04\x95\x02\x00\x00\x00\x00\x00\x00\x00}\x94.")

def create_malicious_pickle(path):
    """
    Creates a REAL malicious pickle file with an RCE payload (os.system).
    Veritensor's engine is designed to detect this 'os.system' global.
    """
    # GLOBAL 'os' 'system' -> TUPLE -> REDUCE
    # This is a classic RCE signature that should trigger a CRITICAL threat.
    path.write_bytes(b"\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x94\x8c\x06system\x94\x93\x94.")

# --- Test Cases ---

def test_cli_scan_clean(tmp_path):
    """
    Test 1: Scan a clean file.
    Expectation: Exit code 0, status PASS.
    """
    f = tmp_path / "clean_model.pkl"
    create_clean_pickle(f)

    result = runner.invoke(app, ["scan", str(f)])
    
    assert result.exit_code == 0
    assert "Scan Passed" in result.stdout

def test_cli_scan_infected(tmp_path):
    """
    Test 2: Scan an infected file.
    Expectation: Exit code 1, status FAIL, deployment blocked.
    """
    f = tmp_path / "infected.pkl"
    create_malicious_pickle(f)

    result = runner.invoke(app, ["scan", str(f)])
    
    # If the engine correctly detects the RCE, exit code must be 1
    if result.exit_code != 1:
        print(f"\n[DEBUG] Unexpected Success. CLI Output:\n{result.stdout}")
        
    assert result.exit_code == 1
    assert "BLOCKING DEPLOYMENT" in result.stdout

def test_cli_ignore_malware(tmp_path):
    """
    Test 3: Scan an infected file with --ignore-malware flag.
    Expectation: Exit code 0, status PASS (with warning).
    """
    f = tmp_path / "ignored_virus.pkl"
    create_malicious_pickle(f)
    
    result = runner.invoke(app, ["scan", str(f), "--ignore-malware"])
    
    # The flag forces exit code 0 despite threats
    assert result.exit_code == 0
    assert "MALWARE/INTEGRITY RISKS DETECTED (Ignored by user)" in result.stdout

def test_cli_ignore_license(tmp_path):
    """
    Test 4: Verify --ignore-license flag.
    Expectation: CLI accepts the flag and processes normally.
    """
    f = tmp_path / "model.pkl"
    create_clean_pickle(f)
    
    result = runner.invoke(app, ["scan", str(f), "--ignore-license"])
    assert result.exit_code == 0

@patch("requests.get")
def test_cli_update(mock_get, tmp_path):
    """
    Test 5: Verify signature update command.
    Mocks a GitHub response and checks if signatures.yaml is created.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = textwrap.dedent("""
    version: "2099.01.01"
    unsafe_globals:
      CRITICAL:
        os: "*"
    """).strip()
    
    mock_get.return_value = mock_response

    # Redirect home directory to tmp_path to avoid modifying real user files
    with patch("pathlib.Path.home", return_value=tmp_path):
        result = runner.invoke(app, ["update"])
        
        assert result.exit_code == 0
        assert "Signatures updated!" in result.stdout
        
        saved_file = tmp_path / ".veritensor" / "signatures.yaml"
        assert saved_file.exists()
        assert "2099.01.01" in saved_file.read_text()

@pytest.mark.skipif(not AWS_AVAILABLE, reason="AWS (boto3) not installed")
def test_s3_scan_flow():
    """
    Test 6: Verify S3 URI handling.
    Checks if the CLI recognizes s3:// schema without immediate crashing.
    """
    result = runner.invoke(app, ["scan", "s3://bucket/model.pkl"])
    # We check that the flow reaches the engine without a Python Traceback
    assert "Traceback" not in result.stdout
