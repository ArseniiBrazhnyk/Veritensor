import pytest
from veritensor.engines.static.rules import is_match, SignatureLoader

def test_regex_matching():
    """Verifies that the regex: prefix is working correctly."""
    pattern = "regex:^meta-llama/.*"
    
    # It should match
    assert is_match("meta-llama/Llama-2-7b", [pattern]) is True
    # It shouldn't match
    assert is_match("google/bert", [pattern]) is False

def test_simple_matching():
    """Checks the good old substring search."""
    pattern = "bert"
    assert is_match("google-bert-base", [pattern]) is True

def test_signatures_loading():
    """Checks that the signatures have loaded (at least the default ones)."""
    globals_dict = SignatureLoader.get_globals()
    assert "CRITICAL" in globals_dict
    assert "os" in globals_dict["CRITICAL"]
    
    injections = SignatureLoader.get_prompt_injections()
    assert len(injections) > 0
