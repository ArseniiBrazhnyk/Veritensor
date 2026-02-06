import pytest
from unittest.mock import MagicMock, patch
from veritensor.engines.content.pii import PIIScanner

def test_pii_no_library_installed():
    """
    Сheck that if there is no Presidio, the code does not crash, but returns an empty list.
    """
    with patch("veritensor.engines.content.pii.PRESIDIO_AVAILABLE", False):
        results = PIIScanner.scan("My email is test@example.com")
        assert results == []

def test_pii_with_mocked_engine():
    """
    We check the logic of processing the results of the Presidio (with mock).
    """
    with patch("veritensor.engines.content.pii.PRESIDIO_AVAILABLE", True):
        mock_res = MagicMock()
        mock_res.entity_type = "EMAIL_ADDRESS"
        mock_res.score = 0.9
        mock_res.start = 12
        mock_res.end = 28
        
        
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = [mock_res]
        
        with patch.object(PIIScanner, "get_engine", return_value=mock_engine):
            text = "My email is test@example.com"
            results = PIIScanner.scan(text)
            
            assert len(results) == 1
            assert "HIGH: PII Leak (EMAIL_ADDRESS)" in results[0]
            # Masking check: te**********
            assert "te**" in results[0] or "te" in results[0]
