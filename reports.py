from __future__ import annotations
import json, html
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from app.config import ROOT

REPORT_DIR = ROOT / "reports"
REPORT_DIR.mkdir(exist_ok=True)

def render_html(report: dict) -> Path:
    path = REPORT_DIR / f"assessment-{report['assessment']['id']}.html"
    data = html.escape(json.dumps(report, indent=2, ensure_ascii=False))
    path.write_text("<!doctype html><html><meta charset='utf-8'><title>K2SecuriTy Assessment</title>"
      "<style>body{font:16px system-ui;max-width:1000px;margin:36px auto;padding:0 20px;color:#172033}"
      "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f8;padding:20px;border-radius:8px}</style>"
      "<h1>K2SecuriTy AI — Assessment Report</h1><p>Automated observations require review; AI analysis is advisory.</p><pre>"
      + data + "</pre></html>", encoding="utf-8")
    return path

def render_json(report: dict) -> Path:
    path = REPORT_DIR / f"assessment-{report['assessment']['id']}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path

def render_pdf(report: dict) -> Path:
    path = REPORT_DIR / f"assessment-{report['assessment']['id']}.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=16*mm, leftMargin=16*mm, topMargin=16*mm, bottomMargin=16*mm)
    story = [Paragraph("K2SecuriTy AI — Assessment Report", styles["Title"]), Spacer(1, 8)]
    story.append(Paragraph("Automated observations require human verification. AI output is advisory.", styles["BodyText"]))
    story.append(Spacer(1, 12))
    text = json.dumps(report, indent=2, ensure_ascii=False)
    # Paragraph-safe monospace text, split to avoid reportlab's huge paragraph limits.
    for line in text.splitlines():
        safe = html.escape(line[:240])
        story.append(Preformatted(safe, styles["Code"]))
    doc.build(story)
    return path
