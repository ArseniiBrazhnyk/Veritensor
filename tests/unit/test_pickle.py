import pytest
from veritensor.engines.static.pickle_engine import scan_pickle_stream

def test_scan_clean_file(clean_model_path):
    with open(clean_model_path, "rb") as f:
        threats = scan_pickle_stream(f.read())
    assert len(threats) == 0

def test_scan_simple_rce(infected_pickle_path):
    with open(infected_pickle_path, "rb") as f:
        threats = scan_pickle_stream(f.read())
    
    # Must find os.system OR nt.system (Windows)
    assert len(threats) > 0
    # Updated assertion to handle Windows 'nt' module
    assert any("os.system" in t or "nt.system" in t or "CRITICAL" in t or "UNSAFE_IMPORT" in t for t in threats)

def test_scan_pytorch_zip(infected_pytorch_path):
    # Zip archive reading test (you need to unpack pickle inside the test or use engine)
    # In the pickle_engine unit test, we only test pickle bytes.
    # We are testing Zip unpacking in an integration test.
    pass
