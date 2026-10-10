from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime, timezone
from app.config import ROOT, settings


def db_path() -> Path:
    url = settings.database_url
    if not url.startswith("sqlite:///"):
        raise RuntimeError("This build currently supports SQLite DATABASE_URL only.")
    raw = url.removeprefix("sqlite:///")
    path = Path(raw)
    return path if path.is_absolute() else (ROOT / path).resolve()


def connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS applications (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS targets (
          id INTEGER PRIMARY KEY, application_id INTEGER, hostname TEXT NOT NULL UNIQUE,
          authorized INTEGER NOT NULL DEFAULT 0, authorization_note TEXT DEFAULT '',
          created_at TEXT NOT NULL, FOREIGN KEY(application_id) REFERENCES applications(id)
        );
        CREATE TABLE IF NOT EXISTS assessments (
          id TEXT PRIMARY KEY, target_id INTEGER NOT NULL, status TEXT NOT NULL,
          started_at TEXT NOT NULL, finished_at TEXT, scanner_ids TEXT NOT NULL,
          error TEXT DEFAULT '', FOREIGN KEY(target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS findings (
          id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, target_id INTEGER NOT NULL,
          title TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
          confidence TEXT NOT NULL, status TEXT NOT NULL, url TEXT NOT NULL,
          description TEXT NOT NULL, evidence_json TEXT NOT NULL, remediation TEXT NOT NULL,
          references_json TEXT NOT NULL, scanner_id TEXT NOT NULL, created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL, FOREIGN KEY(assessment_id) REFERENCES assessments(id),
          FOREIGN KEY(target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS analyses (
          id INTEGER PRIMARY KEY, assessment_id TEXT NOT NULL, prompt TEXT NOT NULL,
          output TEXT NOT NULL, provider TEXT NOT NULL, created_at TEXT NOT NULL,
          FOREIGN KEY(assessment_id) REFERENCES assessments(id)
        );
        CREATE TABLE IF NOT EXISTS audit_events (
          id INTEGER PRIMARY KEY, event_type TEXT NOT NULL, detail_json TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS knowledge_refs (
          id INTEGER PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL,
          url TEXT NOT NULL, source_version TEXT DEFAULT '', source_date TEXT DEFAULT '',
          last_checked TEXT NOT NULL, description TEXT DEFAULT ''
        );
        """)
        count = c.execute("SELECT COUNT(*) FROM knowledge_refs").fetchone()[0]
        if count == 0:
            refs = [
              ("OWASP Top 10", "standard", "https://owasp.org/www-project-top-ten/", "2025", "2025", now(), "Web application risk awareness categories; official page identifies 2025 as the current release."),
              ("OWASP Web Security Testing Guide", "testing-guide", "https://owasp.org/www-project-web-security-testing-guide/stable/", "v4.2 stable", "2020-12-03", now(), "Testing methodology and test identifiers; verify current stable version before citing identifiers."),
              ("OWASP API Security Top 10", "api-security", "https://owasp.org/www-project-api-security/", "2023", "2023", now(), "API security risk categories; verify current project page before citing."),
              ("OWASP Cheat Sheet Series", "guidance", "https://cheatsheetseries.owasp.org/", "", "", now(), "Defensive implementation guidance."),
              ("PortSwigger Web Security Academy", "training", "https://portswigger.net/web-security/all-topics", "", "", now(), "Public educational security material."),
              ("NIST National Vulnerability Database", "cve", "https://nvd.nist.gov/", "", "", now(), "CVE and CVSS information source."),
              ("CVE Program", "cve", "https://www.cve.org/", "", "", now(), "CVE identifiers and program information."),
              ("FIRST CVSS", "scoring", "https://www.first.org/cvss/", "", "", now(), "Common Vulnerability Scoring System reference."),
              ("CWE", "weakness", "https://cwe.mitre.org/", "", "", now(), "Common Weakness Enumeration reference."),
            ]
            c.executemany("INSERT INTO knowledge_refs(title,category,url,source_version,source_date,last_checked,description) VALUES(?,?,?,?,?,?,?)", refs)


def audit(event_type: str, detail: dict) -> None:
    with connect() as c:
        c.execute("INSERT INTO audit_events(event_type,detail_json,created_at) VALUES(?,?,?)",
                  (event_type, json.dumps(detail), now()))
