import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from pathlib import Path
from veritensor.cli.main import app
from veritensor.core.types import ScanResult

runner = CliRunner()

@pytest.fixture
def mock_executor(mocker):
    """
    Mock ProcessPoolExecutor to avoid spawning real processes.
    """
    mock_pool = mocker.patch("concurrent.futures.ProcessPoolExecutor")
    mock_instance = mock_pool.return_value
    mock_instance.__enter__.return_value = mock_instance
    # Ensure shutdown(wait=True) doesn't hang the test
    mock_instance.shutdown.return_value = None
    return mock_instance

@pytest.fixture
def mock_as_completed(mocker):
    """
    Mocks as_completed to return the futures immediately.
    """
    return mocker.patch("concurrent.futures.as_completed")

def test_scan_local_file_clean(tmp_path, mock_executor, mock_as_completed):
    f = tmp_path / "model.pkl"
    f.write_text("fake pickle content")

    # Setup Mock Result
    fake_result = ScanResult(str(f), status="PASS")
    fake_result.file_hash = "sha256:12345"
    
    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    
    # Configure the mocks
    mock_executor.submit.return_value = mock_future
    mock_as_completed.return_value = [mock_future]

    result = runner.invoke(app, ["scan", str(f)])

    assert result.exit_code == 0
    assert "Scan Passed" in result.stdout

def test_scan_malware_blocking(tmp_path, mock_executor, mock_as_completed):
    f = tmp_path / "evil.pkl"
    f.write_text("malware")

    fake_result = ScanResult(str(f), status="FAIL")
    fake_result.add_threat("CRITICAL: RCE Detected")
    
    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    
    mock_executor.submit.return_value = mock_future
    mock_as_completed.return_value = [mock_future]

    result = runner.invoke(app, ["scan", str(f)])

    assert result.exit_code == 1
    assert "BLOCKING DEPLOYMENT" in result.stdout

def test_scan_ignore_malware(tmp_path, mock_executor, mock_as_completed):
    f = tmp_path / "evil.pkl"
    f.write_text("malware")

    fake_result = ScanResult(str(f), status="FAIL")
    fake_result.add_threat("CRITICAL: RCE Detected")
    
    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    
    mock_executor.submit.return_value = mock_future
    mock_as_completed.return_value = [mock_future]

    result = runner.invoke(app, ["scan", str(f), "--ignore-malware"])

    assert result.exit_code == 0
    # FIX: Updated expected string
    assert "SECURITY RISKS DETECTED" in result.stdout
