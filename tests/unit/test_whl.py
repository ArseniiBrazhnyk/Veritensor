import pytest
from veritensor.engines.static.pickle_engine import scan_pickle_stream
from tests.utils.malware_gen import MalwareGenerator

def test_scan_malicious_wheel(tmp_path):
    """
    Integration test:
    1. Generate a .whl file with secrets using MalwareGenerator.
    2. Scan it with pickle_engine (which now supports zip/whl).
    3. Assert that secrets are found.
    """
    # 1. Generate bad wheel
    gen = MalwareGenerator(tmp_path)
    whl_path = gen.create_malicious_wheel()
    
    # 2. Read bytes
    with open(whl_path, "rb") as f:
        content = f.read()
        
    # 3. Scan
    threats = scan_pickle_stream(content)
    
    # 4. Verify detection
    # Should detect AWS Key (Suspicious String)
    assert len(threats) > 0
    assert any("AWS_ACCESS_KEY_ID" in t for t in threats)
    assert any("curl" in t for t in threats)
