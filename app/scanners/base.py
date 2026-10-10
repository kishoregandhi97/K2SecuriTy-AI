from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any
from datetime import datetime, timezone
import uuid

@dataclass
class Finding:
    title: str
    category: str
    severity: str
    confidence: str
    status: str
    url: str
    description: str
    evidence: dict[str, Any]
    remediation: str
    references: list[str]
    scanner_id: str
    id: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        stamp = datetime.now(timezone.utc).isoformat()
        self.created_at = self.created_at or stamp
        self.updated_at = self.updated_at or stamp

    def to_dict(self):
        return asdict(self)

@dataclass
class ScanContext:
    target_url: str
    hostname: str
    pinned_addresses: list[str]
    timeout_seconds: float
    max_response_bytes: int
    request_budget: int

class Scanner:
    scanner_id = "base"
    display_name = "Base scanner"
    version = "0.1.0"
    categories: tuple[str, ...] = ()
    mode = "passive"
    limitations = "Base interface only"

    async def run(self, context: ScanContext) -> list[Finding]:
        raise NotImplementedError
