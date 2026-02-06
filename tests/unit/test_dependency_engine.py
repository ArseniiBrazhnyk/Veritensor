import pytest
from unittest.mock import patch, MagicMock
from veritensor.engines.static.dependency_engine import scan_dependencies, _is_typo

def test_is_typo_logic():
    """
    Validates the core Levenshtein distance algorithm (D=1).
    Ensures substitutions, deletions, and insertions are caught correctly.
    """
    # Substitution
    assert _is_typo("turch", "torch") is True
    # Deletion (checks normalization handling as well)
    assert _is_typo("pndas", "pandas") is True
    # Insertion
    assert _is_typo("ttorch", "torch") is True
    # Normalization check (py_cord vs py-cord should be same, thus distance 0, not 1)
    assert _is_typo("py_cord", "py-cord") is False 
    # Too many differences
    assert _is_typo("tor", "torch") is False

def test_scan_requirements_malware(tmp_path):
    """Checks detection of known malicious entries in requirements.txt."""
    f = tmp_path / "requirements.txt"
    f.write_text("tourch==1.0\nnumpy\n")
    
    with patch("requests.post") as mock_post:
        threats = scan_dependencies(f)
    
    assert any("Known malicious" in t and "tourch" in t for t in threats)

def test_scan_poetry_lock_malware(tmp_path):
    """
    Checks that poetry.lock is correctly parsed and scanned for typos.
    """
    f = tmp_path / "poetry.lock"
    # Simplified poetry.lock format
    content = """
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "pndas"
version = "1.5.0"
"""
    f.write_text(content)
    
    with patch("requests.post") as mock_post:
        threats = scan_dependencies(f)
        
    assert any("Potential Typosquatting" in t and "pandas" in t for t in threats)

@patch("requests.post")
def test_scan_osv_vulnerability(mock_post, tmp_path):
    """
    Tests that vulnerabilities from OSV.dev are correctly reported.
    Matches the specific message format of the new engine.
    """
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.19.0\n")

    # Simulate OSV API response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "results": [{
            "vulns": [{
                "id": "GHSA-m8th-934p-w6h3",
                "summary": "Vulnerability in requests"
            }]
        }]
    }
    mock_post.return_value = mock_response

    threats = scan_dependencies(f)
    
    assert mock_post.called
    # Note: Updated to match "Vulnerability in..." string from latest engine
    assert any("Vulnerability in requests==2.19.0" in t for t in threats)
    assert any("GHSA-m8th-934p-w6h3" in t for t in threats)

def test_scan_pipfile_lock_parsing(tmp_path):
    """Checks parsing logic for Pipfile.lock (JSON format)."""
    f = tmp_path / "Pipfile.lock"
    content = """
    {
        "default": {
            "tourch": {"version": "==1.0.0"}
        }
    }
    """
    f.write_text(content)
    
    with patch("requests.post") as mock_post:
        threats = scan_dependencies(f)
        
    assert any("Known malicious" in t and "tourch" in t for t in threats)

@patch("requests.post")
def test_scan_osv_offline_graceful(mock_post, tmp_path):
    """Ensures scanner doesn't crash on network failure."""
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.19.0\n")

    mock_post.side_effect = Exception("Network unreachable")

    threats = scan_dependencies(f)
    assert isinstance(threats, list)
