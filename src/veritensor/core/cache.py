# Copyright 2026 Veritensor Security Apache 2.0
import sqlite3
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CACHE_FILE = Path.home() / ".veritensor" / "cache.db"

class HashCache:
    def __init__(self):
        self.conn = None
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database and creates the table if not exists."""
        try:
            # Ensure directory exists
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            
            # check_same_thread=False allows using connection across threads.
            # In our multiprocessing architecture, only the MAIN process interacts with this class.
            self.conn = sqlite3.connect(str(CACHE_FILE), check_same_thread=False)
            
            # Enable WAL mode for better performance and concurrency safety
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")
            
            self.cursor = self.conn.cursor()
            
            # Create table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_cache (
                    path TEXT PRIMARY KEY,
                    hash TEXT,
                    size INTEGER,
                    mtime REAL
                )
            """)
            self.conn.commit()
        except Exception as e:
            logger.warning(f"Failed to initialize cache DB: {e}")
            self.conn = None

    def get(self, file_path: Path) -> Optional[str]:
        """Returns the hash if the file has not been changed."""
        if not self.conn: return None

        try:
            abs_path = str(file_path.resolve())
            stats = file_path.stat()
            
            self.cursor.execute(
                "SELECT hash, size, mtime FROM file_cache WHERE path = ?", 
                (abs_path,)
            )
            row = self.cursor.fetchone()
            
            if row:
                cached_hash, cached_size, cached_mtime = row
                # Compare size and mtime (float comparison usually safe for exact system mtime)
                if cached_size == stats.st_size and cached_mtime == stats.st_mtime:
                    return cached_hash
            
            return None
        except Exception:
            # If file not found or permission error during stat
            return None

    def set(self, file_path: Path, file_hash: str):
        """Saves or updates the hash in the cache."""
        if not self.conn: return

        try:
            abs_path = str(file_path.resolve())
            stats = file_path.stat()
            
            self.cursor.execute("""
                INSERT OR REPLACE INTO file_cache (path, hash, size, mtime)
                VALUES (?, ?, ?, ?)
            """, (abs_path, file_hash, stats.st_size, stats.st_mtime))
            
            self.conn.commit()
        except Exception as e:
            logger.debug(f"Cache write error: {e}")

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
