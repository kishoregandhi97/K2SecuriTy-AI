from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from datetime import datetime, timezone
from app.config import ROOT

EVIDENCE_ROOT = ROOT / "evidence"
EVIDENCE_ROOT.mkdir(exist_ok=True)
SECRET_KEYS = re.compile(r"(authorization|cookie|token|password|secret|api[_-]?key|session)", re.I)
BEARER = re.compile(r"(?i)bearer\s+[a-z0-9._~+/-]+=*")

def redact(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if SECRET_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(x) for x in value]
    if isinstance(value, str):
        return BEARER.sub("Bearer [REDACTED]", value[:4000])
    return value

def save_artifact(assessment_id: str, name: str, data: dict) -> dict:
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", assessment_id):
        raise ValueError("Invalid assessment ID")
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)[:80]
    folder = EVIDENCE_ROOT / assessment_id
    folder.mkdir(parents=True, exist_ok=True)
    path = (folder / safe_name).resolve()
    if folder.resolve() not in path.parents:
        raise ValueError("Invalid evidence path")
    raw = json.dumps(redact(data), indent=2, ensure_ascii=False).encode("utf-8")
    path.write_bytes(raw)
    return {"name": safe_name, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
            "redacted": True, "created_at": datetime.now(timezone.utc).isoformat()}

def verify_artifact(assessment_id: str, name: str, expected_sha256: str) -> bool:
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", assessment_id):
        return False
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)[:80]
    path = (EVIDENCE_ROOT / assessment_id / safe_name).resolve()
    folder = (EVIDENCE_ROOT / assessment_id).resolve()
    if folder not in path.parents or not path.is_file():
        return False
    return hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256
