import json
import os
from pathlib import Path
from typing import Optional, Dict

CACHE_FILE = Path(".veritensor_cache.json")

class HashCache:
    def __init__(self):
        self.cache: Dict[str, Dict] = {}
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r") as f:
                    self.cache = json.load(f)
            except Exception:
                self.cache = {}

    def get(self, file_path: Path) -> Optional[str]:
        """Возвращает хэш, если файл не менялся."""
        key = str(file_path.resolve())
        stats = file_path.stat()
        
        if key in self.cache:
            entry = self.cache[key]
            # Проверяем, не изменился ли файл (размер + время изменения)
            if entry["size"] == stats.st_size and entry["mtime"] == stats.st_mtime:
                return entry["hash"]
        return None

    def set(self, file_path: Path, file_hash: str):
        """Сохраняет хэш в кэш."""
        key = str(file_path.resolve())
        stats = file_path.stat()
        self.cache[key] = {
            "hash": file_hash,
            "size": stats.st_size,
            "mtime": stats.st_mtime
        }
        self._save()

    def _save(self):
        with open(CACHE_FILE, "w") as f:
            json.dump(self.cache, f, indent=2)
