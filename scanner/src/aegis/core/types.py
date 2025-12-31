from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class ScanResult:
    file_path: str
    status: str = "PASS"  # PASS / FAIL
    threats: List[str] = field(default_factory=list)
    file_hash: Optional[str] = None
    identity_verified: bool = False
    
    def add_threat(self, message: str):
        self.threats.append(message)
        self.status = "FAIL"
