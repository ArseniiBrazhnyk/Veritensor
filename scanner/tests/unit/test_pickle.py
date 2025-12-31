import pytest
from aegis.engines.static.pickle_engine import scan_pickle_stream

def test_scan_clean_file(clean_model_path):
    with open(clean_model_path, "rb") as f:
        threats = scan_pickle_stream(f.read())
    assert len(threats) == 0

def test_scan_simple_rce(infected_pickle_path):
    with open(infected_pickle_path, "rb") as f:
        threats = scan_pickle_stream(f.read())
    
    # Должен найти os.system
    assert len(threats) > 0
    assert any("os.system" in t or "CRITICAL" in t for t in threats)

def test_scan_pytorch_zip(infected_pytorch_path):
    # Тест на чтение zip-архива (нужно распаковать pickle внутри теста или использовать engine)
    # В unit-тесте pickle_engine мы тестируем только байты pickle.
    # Распаковку Zip тестируем в интеграционном тесте.
    pass
