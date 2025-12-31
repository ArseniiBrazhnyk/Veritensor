import pytest
from unittest.mock import patch, MagicMock
from veritensor.integrations.cosign import sign_container

@patch("veritensor.integrations.cosign.subprocess.run")
@patch("veritensor.integrations.cosign.is_cosign_available", return_value=True)
@patch("pathlib.Path.exists", return_value=True) # Simulating the presence of a key
def test_sign_container_success(mock_exists, mock_avail, mock_run):
    # Setting up the ioc so that it returns "Success"
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "Signed successfully"
    mock_run.return_value = mock_proc

    result = sign_container("my-image:v1", "key.pem")
    
    assert result is True
    # We check that cosign was called with the correct flags.
    args = mock_run.call_args[0][0]
    assert "cosign" in args
    assert "sign" in args
    assert "--tlog-upload=false" in args # Default Privacy
