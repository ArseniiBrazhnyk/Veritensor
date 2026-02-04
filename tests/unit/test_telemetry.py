import pytest
from unittest.mock import patch, MagicMock
from veritensor.reporting.telemetry import send_report
from veritensor.core.config import VeritensorConfig
from veritensor.core.types import ScanResult

def test_telemetry_success():
    """Check that everything runs smoothly at 200 OK."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    
    results = [ScanResult(file_path="test.pt", file_hash="123", status="PASS")]
    config = VeritensorConfig(report_url="http://fake.url", api_key="123")

    with patch("requests.post", return_value=mock_response) as mock_post:
        send_report(results, config)
        mock_post.assert_called_once()
        # Checking that the JSON has been sent
        args, kwargs = mock_post.call_args
        assert kwargs["json"]["scan_summary"]["total_files"] == 1

def test_telemetry_fail_open():
    """CRITICAL: We check that the CLI does NOT CRASH if the server is down."""
    results = [ScanResult(file_path="test.pt")]
    config = VeritensorConfig(report_url="http://broken.url")

    # Emulating a network error
    with patch("requests.post", side_effect=Exception("Connection refused")):
        try:
            send_report(results, config)
        except Exception:
            pytest.fail("Telemetry crashed the application! It should fail silently.")
