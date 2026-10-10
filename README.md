# K2SecuriTy AI

Local-first, evidence-led web security assessment workbench for **authorized** targets. The project is deliberately honest about implementation status: the currently executable scanners are passive HTTP/TLS configuration checks and conservative API-schema metadata checks. Other scanner families appear in the UI as Planned or Manual Review Required; they do not return fake findings.

## Current milestone status

### Implemented in this build
- FastAPI application and responsive dark dashboard with working pages for applications, target registration, scanner status, findings, AI analysis, evidence, reports, knowledge references, history, remediation status, and settings.
- SQLite persistence for applications, exact-host targets, assessments, findings, analysis history, audit events, and knowledge references.
- Explicit authorization flag and authorization note for each registered target.
- HTTPS-only, port-443-only target parsing; exact hostname match; public-address policy; rejection of private, loopback, link-local, multicast, reserved, and unspecified addresses.
- HTTP/TLS scanner using a custom `aiohttp` resolver pinned to validated addresses, with certificate verification, no environment proxy, no automatic redirects, exact-host redirect revalidation, redirect cap, response size limit, and timeout.
- Security misconfiguration metadata scanner that checks four bounded API-schema locations without following redirects or storing full response bodies.
- Conservative header and cookie attribute observations. Missing headers are low/informational hardening observations, not automatic claims of exploitability.
- Redacted local JSON evidence artifacts with SHA-256 digest and integrity verification endpoint.
- AI analysis via Ollama's OpenAI-compatible endpoint or another compatible Chat Completions API. AI is optional; disabled by default. AI analysis is advisory and does not update finding status.
- JSON, HTML, and PDF report exports.
- Seeded official reference catalog and a manual timestamp refresh function. The timestamp function does not download or validate source contents.
- Basic unit and API tests with mocked/local-only logic.

### Not implemented yet
Directory listing and backup-file probing, injection tests, authentication/session testing with test accounts, access-control comparison tests, API/OpenAPI inventory, JavaScript source analysis, active SSRF validation, file-upload tests, comprehensive information-disclosure checks, SBOM/CVE synchronization, business-logic automation, browser screenshots, cancellation of a running scan, and full TLS protocol/cipher enumeration. These are shown as Planned or Manual Review Required. Do not infer that the app currently tests these classes.

## Safety model and important limitations

- This application is intended for local use and binds to `127.0.0.1` by default. Do not expose it to the public Internet; authentication and multi-user authorization are not implemented.
- Public accessibility is not authorization. A target must be registered and marked authorized and the operator must confirm permission when starting an assessment.
- Scope uses exact hostnames only. Wildcards and arbitrary subdomains are not supported. If `ALLOWED_HOSTS` is populated, the hostname must also be listed there.
- Network checks are restricted to HTTPS on port 443 and publicly routable addresses. DNS results are checked again before a request and pinned into the scanner's resolver. If the DNS answer changes between validation and connection setup, the request is aborted. Keep the app updated and run only with an approved target.
- The UI authorization checkbox is an operator confirmation, not independent proof of ownership or permission.
- Query-string values are redacted in stored finding URLs; response bodies are not stored by default, and response samples are represented by hashes and sizes. Evidence is redacted where possible, but assessors must still inspect it before sharing. AI prompts and selected evidence are sent to the configured model provider. Use local Ollama if evidence should not leave the machine.
- SQLite and local evidence are not encrypted at rest by this app. Use OS disk protections and appropriate filesystem permissions.

## Requirements

- Python 3.11+
- Kali Linux or another supported Python environment
- Network access to an authorized HTTPS target for real assessments
- Optional: Ollama installed locally, or an OpenAI-compatible API provider

## Kali Linux installation

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git unzip
unzip K2SecuriTy-AI.zip
cd K2SecuriTy-AI
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
nano .env
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in Chromium. API documentation is available locally at `http://127.0.0.1:8000/docs`.

For a GitHub clone, use `git clone https://github.com/YOUR_USERNAME/K2SecuriTy-AI.git` and then `cd K2SecuriTy-AI` instead of unzipping.

Convenience scripts:

```bash
./setup.sh
./run.sh
```

`run.sh` binds to localhost. Stop it with `Ctrl+C`.

## Configure Ollama

Install and start Ollama according to its official installation instructions, then pull a model you have available. Example only:

```bash
ollama pull qwen3:1.7b
```

In `.env`:

```dotenv
AI_ENABLED=true
AI_BASE_URL=http://127.0.0.1:11434/v1
AI_API_KEY=ollama
AI_MODEL=qwen3:1.7b
```

Restart Uvicorn after changing `.env`. Verify `GET /api/health` reports `ai_enabled: true`. Model names vary by installed Ollama library; use `ollama list` to check the exact model name.

## Configure a hosted AI provider

The provider must support the OpenAI-compatible `POST {AI_BASE_URL}/chat/completions` API and return `choices[0].message.content`. Set `AI_BASE_URL`, `AI_API_KEY`, `AI_MODEL`, and `AI_ENABLED=true` in `.env`. Never place secrets in frontend files or commit `.env`. The UI does not display API keys.

## Workflow

1. Create an application in **Applications** (optional grouping).
2. Register an exact hostname in **Authorized Targets** and record the permission/approval reference. Tick authorization only when you have explicit permission.
3. Enter an HTTPS URL for that exact hostname and run **HTTP and TLS Configuration**.
4. Review observations in **All Findings**. A missing header is a hardening observation, not proof of exploitation.
5. Select the assessment in **AI Security Analyst**, edit the prompt, and submit selected evidence for advisory analysis.
6. Export JSON, HTML, or PDF from **Reports** or Assessment History.
7. Change finding status only after human review; changes are written to audit events.

## API endpoints

- `GET /api/health`
- `GET/POST /api/applications`
- `GET/POST /api/targets`
- `PATCH /api/targets/{id}/authorization`
- `GET /api/scanners`
- `POST /api/assessments`
- `GET /api/assessments` and `GET /api/assessments/{id}`
- `GET /api/findings` and `PATCH /api/findings/{id}`
- `POST /api/ai/analyze`, `GET /api/ai/history`
- `GET /api/knowledge`, `POST /api/knowledge/check`
- `GET /api/reports/{assessment_id}/{json|html|pdf}`
- `GET /api/evidence/{assessment_id}/verify?name=scan-evidence.json&sha256=...`
- `GET /api/audit`

## Testing

```bash
source .venv/bin/activate
pytest -q
```

The unit tests do not scan public targets. Real network assessment is not part of the test suite.

## Official reference catalog

The app seeds links to these official references. It does not bundle their full contents or claim that the local catalog is a synchronized vulnerability database:

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP WSTG stable: https://owasp.org/www-project-web-security-testing-guide/stable/
- OWASP API Security: https://owasp.org/www-project-api-security/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- PortSwigger Web Security Academy: https://portswigger.net/web-security/all-topics
- NIST NVD: https://nvd.nist.gov/
- CVE Program: https://www.cve.org/
- FIRST CVSS: https://www.first.org/cvss/
- CWE: https://cwe.mitre.org/

Respect each source's license, attribution, rate limits, and terms when building future synchronization. WSTG test identifiers should be versioned in future finding mappings because identifiers can change between versions.

## Troubleshooting

- **`ModuleNotFoundError`**: activate `.venv`, then run `pip install -r requirements.txt`.
- **Port 8000 is busy**: stop the old server or use `uvicorn app.main:app --host 127.0.0.1 --port 8001` and open port 8001 locally.
- **AI returns 503**: confirm `AI_ENABLED=true` and restart Uvicorn.
- **AI returns 502**: verify provider base URL, model name, connectivity, and compatibility with OpenAI Chat Completions. Do not print or share your key in logs.
- **Target rejected**: ensure the target is authorized in the app, hostname matches exactly, URL uses HTTPS port 443, DNS resolves only to public addresses, and `ALLOWED_HOSTS` (if set) includes it.
- **Database error**: check that `data/` exists and is writable by the normal Kali user.
- **Certificate or connection error**: scanner uses certificate verification and will not bypass invalid certificates. Investigate the target certificate rather than disabling verification.

## License

MIT for the original application code. External standards and references remain subject to their respective licenses and terms.
