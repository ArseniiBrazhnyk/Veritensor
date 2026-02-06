import pytest
from unittest.mock import patch, MagicMock
from veritensor.engines.static.dependency_engine import scan_dependencies, _is_typo

def test_is_typo_logic():
    """
    Validates the core Levenshtein distance algorithm (D=1).
    Ensures substitutions, deletions, and insertions are caught.
    """
    # Substitution: 'u' instead of 'o'
    assert _is_typo("turch", "torch") is True
    # Deletion: missing 'r'
    assert _is_typo("toch", "torch") is True
    # Insertion: extra 't'
    assert _is_typo("ttorch", "torch") is True
    # Too many differences (Distance > 1)
    assert _is_typo("tor", "torch") is False
    # Identical strings (Distance = 0)
    assert _is_typo("torch", "torch") is False

def test_scan_requirements_malware(tmp_path):
    """
    Checks detection of known malicious entries in requirements.txt.
    Wraps network calls to ensure static analysis works offline.
    """
    f = tmp_path / "requirements.txt"
    f.write_text("tourch==1.0\nnumpy\n")
    
    with patch("requests.post") as mock_post:
        threats = scan_dependencies(f)
    
    assert any("Known malicious" in t and "tourch" in t for t in threats)

def test_scan_requirements_typo(tmp_path):
    """
    Checks typosquatting detection for popular packages in requirements.txt.
    """
    f = tmp_path / "requirements.txt"
    f.write_text("pndas>=1.0\n")
    
    with patch("requests.post") as mock_post:
        threats = scan_dependencies(f)
        
    assert any("Potential Typosquatting" in t and "pandas" in t for t in threats)

def test_scan_toml_dependencies(tmp_path):
    """
    Checks parsing and detection within pyproject.toml format.
    """
    f = tmp_path / "pyproject.toml"
    f.write_text("""
    [project.dependencies]
    torch = ">=2.0"
    reqests = "0.1"
    """)
    
    with patch("requests.post") as mock_post:
        threats = scan_dependencies(f)
        
    assert any("Potential Typosquatting" in t and "requests" in t for t in threats)

@patch("requests.post")
def test_scan_osv_vulnerability(mock_post, tmp_path):
    """
    Tests that CVEs from OSV.dev API are correctly parsed and reported.
    Uses MagicMock to simulate a successful API response with vulnerabilities.
    """
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.19.0\n")

    # Simulate successful API response with one vulnerability
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
    
    # Verify API was called and threat was recorded
    assert mock_post.called
    assert any("CVE Detected in requests==2.19.0" in t for t in threats)
    assert any("GHSA-m8th-934p-w6h3" in t for t in threats)

@patch("requests.post")
def test_scan_osv_offline_graceful(mock_post, tmp_path):
    """
    Ensures the scanner handles network failures gracefully.
    If OSV.dev is down, the scanner should continue without crashing.
    """
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.19.0\n")

    # Simulate network timeout/failure
    mock_post.side_effect = Exception("Connection timeout")

    threats = scan_dependencies(f)
    
    # Should return a valid list (might be empty or contain static results)
    assert isinstance(threats, list)
