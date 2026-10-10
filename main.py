from __future__ import annotations
import json, uuid, asyncio
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from app.config import ROOT, settings
from app.database import init_db, connect, now, audit
from app.services.scope import normalize_host, require_target_scope, redact_url
from app.services.evidence import save_artifact, verify_artifact
from app.scanners.base import ScanContext
from app.scanners.registry import SCANNERS, PLANNED_SCANNERS
from app.ai.provider import analyze as run_ai_analysis
from app.reporting.reports import render_html, render_json, render_pdf

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="K2SecuriTy AI", version="0.1.0", description="Local-first authorized security assessment workbench", lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])
app.mount("/static", StaticFiles(directory=ROOT / "app" / "static"), name="static")


class ApplicationIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)

class TargetIn(BaseModel):
    hostname: str = Field(min_length=3, max_length=253)
    application_id: int | None = None
    authorized: bool = False
    authorization_note: str = Field(default="", max_length=500)

class ScanIn(BaseModel):
    target_id: int
    target_url: str = Field(min_length=8, max_length=2048)
    scanner_ids: list[str] = Field(default_factory=lambda: ["http_tls"], min_length=1, max_length=4)
    confirm_authorized: bool = False

class StatusIn(BaseModel):
    status: str
    severity: str | None = None
    confidence: str | None = None
    remediation_note: str | None = None

class AnalyzeIn(BaseModel):
    assessment_id: str
    prompt: str = Field(min_length=3, max_length=12000)
    finding_ids: list[str] = Field(default_factory=list, max_length=50)
    send_to_hosted_provider: bool = False

@app.get("/", response_class=HTMLResponse)
def home():
    return FileResponse(ROOT / "app" / "static" / "index.html")

@app.get("/api/health")
def health():
    ai_host = (urlsplit(settings.ai_base_url).hostname or "").lower()
    ai_is_local = ai_host in {"localhost", "127.0.0.1", "::1"}
    return {"status": "ok", "ai_enabled": settings.ai_enabled, "ai_model": settings.ai_model if settings.ai_enabled else None,
            "ai_is_local": ai_is_local, "ai_endpoint_host": ai_host or None, "database": "sqlite", "scanner_count": len(SCANNERS)}

@app.get("/api/dashboard")
def dashboard():
    with connect() as c:
        applications = c.execute("SELECT COUNT(*) FROM applications").fetchone()[0]
        targets = c.execute("SELECT COUNT(*) FROM targets WHERE authorized=1").fetchone()[0]
        findings = c.execute("SELECT status, severity, COUNT(*) n FROM findings GROUP BY status,severity").fetchall()
        assessments = c.execute("SELECT a.*,t.hostname FROM assessments a JOIN targets t ON t.id=a.target_id ORDER BY a.started_at DESC LIMIT 8").fetchall()
        total_findings = sum(r["n"] for r in findings)
        remediated = sum(r["n"] for r in findings if r["status"] == "Remediated")
        exceptions = sum(r["n"] for r in findings if r["status"] == "Accepted Risk")
        by_status = {}
        by_severity = {}
        for row in findings:
            by_status[row["status"]] = by_status.get(row["status"], 0) + row["n"]
            by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + row["n"]
        recent = [dict(r) for r in assessments]
        for r in recent:
            r["scanner_ids"] = json.loads(r["scanner_ids"])
        trend_rows = c.execute("SELECT substr(created_at,1,7) AS month, severity, COUNT(*) AS n FROM findings WHERE created_at >= date('now','-5 months','start of month') GROUP BY month,severity ORDER BY month").fetchall()
        trend_map = {}
        for row in trend_rows:
            trend_map.setdefault(row["month"], {})[row["severity"]] = row["n"]
    monthly_trend = [{"month": month, "counts": trend_map.get(month, {})} for month in sorted(trend_map)]
    return {"applications": applications, "authorized_targets": targets, "total_findings": total_findings,
            "remediated_findings": remediated, "exceptions": exceptions, "status_counts": by_status,
            "severity_counts": by_severity, "monthly_trend": monthly_trend, "recent_assessments": recent}

@app.get("/api/applications")
def list_applications():
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM applications ORDER BY id DESC")]

@app.post("/api/applications")
def create_application(data: ApplicationIn):
    with connect() as c:
        cur = c.execute("INSERT INTO applications(name,description,created_at) VALUES(?,?,?)", (data.name.strip(), data.description.strip(), now()))
        app_id = cur.lastrowid
    audit("application.created", {"application_id": app_id})
    return {"id": app_id, "name": data.name.strip()}

@app.get("/api/targets")
def list_targets():
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT t.*,a.name application_name FROM targets t LEFT JOIN applications a ON a.id=t.application_id ORDER BY t.id DESC")]

@app.post("/api/targets")
def create_target(data: TargetIn):
    try:
        hostname = normalize_host(data.hostname)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if data.application_id is not None:
        with connect() as c:
            if not c.execute("SELECT 1 FROM applications WHERE id=?", (data.application_id,)).fetchone():
                raise HTTPException(404, "Application not found")
    try:
        with connect() as c:
            cur = c.execute("INSERT INTO targets(application_id,hostname,authorized,authorization_note,created_at) VALUES(?,?,?,?,?)",
                (data.application_id, hostname, int(data.authorized), data.authorization_note.strip(), now()))
            target_id = cur.lastrowid
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPException(409, "Target hostname already registered") from exc
        raise
    audit("target.created", {"target_id": target_id, "hostname": hostname, "authorized": data.authorized})
    return {"id": target_id, "hostname": hostname, "authorized": data.authorized}

@app.patch("/api/targets/{target_id}/authorization")
def set_target_authorization(target_id: int, data: dict):
    authorized = data.get("authorized")
    note = str(data.get("authorization_note", ""))[:500]
    if not isinstance(authorized, bool):
        raise HTTPException(400, "authorized must be a boolean")
    with connect() as c:
        cur = c.execute("UPDATE targets SET authorized=?,authorization_note=? WHERE id=?", (int(authorized), note, target_id))
        if not cur.rowcount:
            raise HTTPException(404, "Target not found")
    audit("target.authorization_changed", {"target_id": target_id, "authorized": authorized})
    return {"id": target_id, "authorized": authorized}

@app.get("/api/scanners")
def scanners():
    implemented = [{"id": k, "name": v.display_name, "version": v.version, "categories": list(v.categories),
                    "mode": v.mode, "status": "Implemented", "limitations": v.limitations} for k, v in SCANNERS.items()]
    return implemented + PLANNED_SCANNERS

async def run_assessment(assessment_id: str, target: dict, target_url: str, scanner_ids: list[str]):
    try:
        try:
            host, port, clean_url, addresses = require_target_scope(target_url, target["hostname"], bool(target["authorized"]), settings.allowed_hosts)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        ctx = ScanContext(clean_url, host, addresses, settings.request_timeout_seconds,
                          settings.max_response_bytes, min(settings.requests_per_scan, 12))
        all_findings = []
        for scanner_id in scanner_ids:
            scanner = SCANNERS[scanner_id]
            findings = await scanner.run(ctx)
            all_findings.extend(findings)
        with connect() as c:
            for finding in all_findings:
                item = finding.to_dict()
                # Deduplicate same title, URL and scanner for this assessment.
                existing = c.execute("SELECT id FROM findings WHERE assessment_id=? AND title=? AND url=? AND scanner_id=?",
                    (assessment_id, item["title"], item["url"], item["scanner_id"])).fetchone()
                if existing:
                    continue
                c.execute("INSERT INTO findings(id,assessment_id,target_id,title,category,severity,confidence,status,url,description,evidence_json,remediation,references_json,scanner_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (item["id"], assessment_id, target["id"], item["title"], item["category"], item["severity"], item["confidence"], item["status"], item["url"], item["description"], json.dumps(item["evidence"]), item["remediation"], json.dumps(item["references"]), item["scanner_id"], item["created_at"], item["updated_at"]))
        artifact = save_artifact(assessment_id, "scan-evidence.json", {"assessment_id": assessment_id, "target": target["hostname"], "target_url": redact_url(clean_url), "pinned_addresses": addresses, "findings": [f.to_dict() for f in all_findings]})
        with connect() as c:
            c.execute("UPDATE assessments SET status='completed',finished_at=? WHERE id=?", (now(), assessment_id))
        audit("assessment.completed", {"assessment_id": assessment_id, "finding_count": len(all_findings), "evidence_sha256": artifact["sha256"]})
        return {"assessment_id": assessment_id, "status": "completed", "finding_count": len(all_findings), "evidence": artifact}
    except Exception as exc:
        with connect() as c:
            c.execute("UPDATE assessments SET status='failed',finished_at=?,error=? WHERE id=?", (now(), str(exc)[:500], assessment_id))
        if isinstance(exc, HTTPException):
            raise exc
        raise HTTPException(502, f"Assessment failed: {type(exc).__name__}") from exc

@app.post("/api/assessments")
async def start_assessment(data: ScanIn):
    if not data.confirm_authorized:
        raise HTTPException(403, "Confirm that you are authorized to assess this target")
    if not data.scanner_ids or any(x not in SCANNERS for x in data.scanner_ids):
        raise HTTPException(400, "One or more scanner modules are not implemented or not selectable")
    with connect() as c:
        row = c.execute("SELECT * FROM targets WHERE id=?", (data.target_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Target not found")
        target = dict(row)
        if not target["authorized"]:
            raise HTTPException(403, "Target is not marked authorized in the target registry")
        assessment_id = str(uuid.uuid4())
        c.execute("INSERT INTO assessments(id,target_id,status,started_at,scanner_ids) VALUES(?,?,?,?,?)",
                  (assessment_id, target["id"], "running", now(), json.dumps(data.scanner_ids)))
    audit("assessment.started", {"assessment_id": assessment_id, "target_id": target["id"], "scanner_ids": data.scanner_ids})
    return await run_assessment(assessment_id, target, data.target_url, data.scanner_ids)

@app.get("/api/assessments")
def list_assessments():
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT a.*,t.hostname FROM assessments a JOIN targets t ON t.id=a.target_id ORDER BY a.started_at DESC LIMIT 200")]

@app.get("/api/assessments/{assessment_id}")
def get_assessment(assessment_id: str):
    with connect() as c:
        row = c.execute("SELECT a.*,t.hostname FROM assessments a JOIN targets t ON t.id=a.target_id WHERE a.id=?", (assessment_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Assessment not found")
        findings = [dict(r) for r in c.execute("SELECT * FROM findings WHERE assessment_id=? ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END", (assessment_id,))]
    for f in findings:
        f["evidence"] = json.loads(f.pop("evidence_json")); f["references"] = json.loads(f.pop("references_json"))
    result = dict(row); result["scanner_ids"] = json.loads(result["scanner_ids"]); result["findings"] = findings
    return result

@app.get("/api/findings")
def list_findings(status: str | None = None, severity: str | None = None, q: str | None = Query(default=None, max_length=100)):
    sql = "SELECT f.*,t.hostname FROM findings f JOIN targets t ON t.id=f.target_id WHERE 1=1"
    args: list = []
    if status:
        sql += " AND f.status=?"; args.append(status)
    if severity:
        sql += " AND f.severity=?"; args.append(severity)
    if q:
        sql += " AND (f.title LIKE ? OR f.url LIKE ? OR t.hostname LIKE ?)"; args.extend([f"%{q}%"]*3)
    sql += " ORDER BY f.created_at DESC LIMIT 500"
    with connect() as c:
        rows = [dict(r) for r in c.execute(sql, args)]
    for f in rows:
        f["evidence"] = json.loads(f.pop("evidence_json")); f["references"] = json.loads(f.pop("references_json"))
    return rows

@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: str, data: StatusIn):
    allowed_status = {"Potential", "Needs Manual Verification", "Confirmed", "Remediated", "Accepted Risk", "False Positive", "Inconclusive"}
    allowed_severity = {"Critical", "High", "Medium", "Low", "Informational"}
    allowed_confidence = {"Low", "Medium", "High"}
    if data.status not in allowed_status:
        raise HTTPException(400, "Invalid finding status")
    if data.severity and data.severity not in allowed_severity:
        raise HTTPException(400, "Invalid severity")
    if data.confidence and data.confidence not in allowed_confidence:
        raise HTTPException(400, "Invalid confidence")
    with connect() as c:
        row = c.execute("SELECT id,status,severity,confidence FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Finding not found")
        severity = data.severity or row["severity"]
        confidence = data.confidence or row["confidence"]
        c.execute("UPDATE findings SET status=?,severity=?,confidence=?,updated_at=? WHERE id=?", (data.status, severity, confidence, now(), finding_id))
    audit("finding.updated", {"finding_id": finding_id, "from_status": row["status"], "to_status": data.status, "severity": severity, "confidence": confidence, "note": (data.remediation_note or "")[:500]})
    return {"id": finding_id, "status": data.status, "severity": severity, "confidence": confidence}

@app.post("/api/ai/analyze")
async def ai_analyze(data: AnalyzeIn):
    with connect() as c:
        assessment = c.execute("SELECT a.*,t.hostname FROM assessments a JOIN targets t ON t.id=a.target_id WHERE a.id=?", (data.assessment_id,)).fetchone()
        if not assessment:
            raise HTTPException(404, "Assessment not found")
        if data.finding_ids:
            marks = ",".join("?" for _ in data.finding_ids)
            rows = c.execute(f"SELECT id,title,severity,confidence,status,url,description,evidence_json,remediation,references_json FROM findings WHERE assessment_id=? AND id IN ({marks})", [data.assessment_id, *data.finding_ids]).fetchall()
        else:
            rows = c.execute("SELECT id,title,severity,confidence,status,url,description,evidence_json,remediation,references_json FROM findings WHERE assessment_id=? LIMIT 30", (data.assessment_id,)).fetchall()
    context = {"assessment": {"id": assessment["id"], "hostname": assessment["hostname"], "status": assessment["status"]},
               "findings": [{**{k: r[k] for k in ["id","title","severity","confidence","status","url","description","remediation"]}, "evidence": json.loads(r["evidence_json"]), "references": json.loads(r["references_json"])} for r in rows]}
    try:
        output, model = await run_ai_analysis(data.prompt, context)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"AI provider request failed: {type(exc).__name__}") from exc
    with connect() as c:
        c.execute("INSERT INTO analyses(assessment_id,prompt,output,provider,created_at) VALUES(?,?,?,?,?)", (data.assessment_id, data.prompt, output, model, now()))
    audit("ai.analysis_created", {"assessment_id": data.assessment_id, "model": model, "finding_count": len(rows)})
    return {"assessment_id": data.assessment_id, "model": model, "analysis": output, "finding_count": len(rows), "advisory_only": True}

@app.get("/api/ai/history")
def ai_history(assessment_id: str | None = None):
    with connect() as c:
        if assessment_id:
            rows = c.execute("SELECT id,assessment_id,prompt,output,provider,created_at FROM analyses WHERE assessment_id=? ORDER BY id DESC", (assessment_id,)).fetchall()
        else:
            rows = c.execute("SELECT id,assessment_id,prompt,output,provider,created_at FROM analyses ORDER BY id DESC LIMIT 100").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/knowledge")
def knowledge():
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM knowledge_refs ORDER BY category,title")]

@app.post("/api/knowledge/check")
def knowledge_manual_check():
    # This records a manual check timestamp only. It does not pretend to download or validate sources.
    with connect() as c:
        c.execute("UPDATE knowledge_refs SET last_checked=?", (now(),))
        count = c.execute("SELECT COUNT(*) FROM knowledge_refs").fetchone()[0]
    audit("knowledge.manual_check_timestamp", {"entries": count})
    return {"updated_entries": count, "note": "Only local timestamps updated. Source content was not fetched or validated."}

@app.get("/api/reports/{assessment_id}/{format}")
def export_report(assessment_id: str, format: str):
    if format not in {"json", "html", "pdf"}:
        raise HTTPException(400, "Supported formats: json, html, pdf")
    report = get_assessment(assessment_id)
    if format == "json": path = render_json({"assessment": {k:v for k,v in report.items() if k != "findings"}, "findings": report["findings"]}); media = "application/json"
    elif format == "html": path = render_html({"assessment": {k:v for k,v in report.items() if k != "findings"}, "findings": report["findings"]}); media = "text/html"
    else: path = render_pdf({"assessment": {k:v for k,v in report.items() if k != "findings"}, "findings": report["findings"]}); media = "application/pdf"
    return FileResponse(path, media_type=media, filename=path.name)

@app.get("/api/evidence/{assessment_id}/verify")
def evidence_verify(assessment_id: str, name: str = "scan-evidence.json", sha256: str = Query(min_length=64, max_length=64)):
    return {"assessment_id": assessment_id, "name": name, "integrity_valid": verify_artifact(assessment_id, name, sha256)}

@app.get("/api/audit")
def audit_events():
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 200")]
