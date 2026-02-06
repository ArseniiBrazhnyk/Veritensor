import pytest
import os
import time
from veritensor.core.cache import HashCache

def test_cache_init(tmp_path, mocker):
    """Verifies that the database and table are created correctly."""
    db_path = tmp_path / "init_test.db"
    mocker.patch("veritensor.core.cache.CACHE_FILE", db_path)
    
    cache = HashCache()
    try:
        assert db_path.exists()
    finally:
        cache.close()

def test_cache_set_get(tmp_path, mocker):
    """Verifies setting, getting, and mtime-based invalidation."""
    db_path = tmp_path / "logic_test.db"
    mocker.patch("veritensor.core.cache.CACHE_FILE", db_path)

    f = tmp_path / "model.pt"
    f.write_text("original content")
    
    cache = HashCache()
    
    try:
        # 1. Set the initial cache
        cache.set(f, "hash_v1")
        
        # 2. Get (Should be a HIT)
        assert cache.get(f) == "hash_v1"
        
        # 3. Simulate file modification with GUARANTEED mtime change
        # We manually set the access/modified time to 1 hour in the future 
        # to avoid CI clock precision issues.
        future_time = time.time() + 3600 
        f.write_text("modified content")
        os.utime(f, (future_time, future_time))
        
        # 4. Get (Should be a MISS)
        # The cache stores the mtime from when .set() was called. 
        # Since we just updated the file's mtime, it shouldn't match.
        result = cache.get(f)
        assert result is None, f"Expected cache miss, but got {result}"

    finally:
        # CRITICAL: Always close to release the SQLite lock
        cache.close()
