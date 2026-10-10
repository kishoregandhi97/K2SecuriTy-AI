from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/k2security.db")
    request_timeout_seconds: float = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "8"))
    requests_per_scan: int = int(os.getenv("REQUESTS_PER_SCAN", "12"))
    max_response_bytes: int = int(os.getenv("MAX_RESPONSE_BYTES", "65536"))
    ai_enabled: bool = os.getenv("AI_ENABLED", "false").strip().lower() == "true"
    ai_base_url: str = os.getenv("AI_BASE_URL", "http://127.0.0.1:11434/v1").rstrip("/")
    ai_api_key: str = os.getenv("AI_API_KEY", "ollama")
    ai_model: str = os.getenv("AI_MODEL", "qwen3:1.7b")
    ai_timeout_seconds: float = float(os.getenv("AI_TIMEOUT_SECONDS", "45"))
    allowed_hosts: tuple[str, ...] = tuple(
        x.strip().lower().rstrip(".") for x in os.getenv("ALLOWED_HOSTS", "").split(",") if x.strip()
    )

settings = Settings()
