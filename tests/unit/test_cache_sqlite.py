import pytest
import sqlite3
from veritensor.core.cache import HashCache, CACHE_FILE

@pytest.fixture
def mock_cache_path(tmp_path, mocker):
    """Redirects the cache file to a temp directory."""
    new_path = tmp_path / "cache.db"
    mocker.patch("veritensor.core.cache.CACHE_FILE", new_path)
    return new_path

def test_cache_init(mock_cache_path):
    cache = HashCache()
    assert mock_cache_path.exists()
    
    # Check if table exists
    conn = sqlite3.connect(str(mock_cache_path))
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file_cache';")
    assert cursor.fetchone() is not None
    cache.close()

def test_cache_set_get(mock_cache_path, tmp_path):
    # 1. Setup file
    f = tmp_path / "model.pt"
    f.write_text("data")
    
    cache = HashCache()
    
    # 2. Set hash
    cache.set(f, "hash_123")
    
    # 3. Get hash (Should hit)
    retrieved = cache.get(f)
    assert retrieved == "hash_123"
    
    # 4. Modify file (mtime changes)
    import time
    time.sleep(0.01) # ensure mtime diff
    f.write_text("new data")
    
    # 5. Get hash (Should miss because mtime changed)
    retrieved_after_edit = cache.get(f)
    assert retrieved_after_edit is None
    
    cache.close()
