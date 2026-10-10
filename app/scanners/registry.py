from app.scanners.http_tls import HttpTlsScanner
from app.scanners.misconfiguration import MisconfigurationScanner

SCANNERS = {
    "http_tls": HttpTlsScanner(),
    "misconfiguration": MisconfigurationScanner(),
}

PLANNED_SCANNERS = [
    {"id": "injection", "name": "Injection Assessment", "status": "Planned", "reason": "Requires controlled lab fixtures and category-specific validation."},
    {"id": "authentication", "name": "Authentication and Sessions", "status": "Manual Review Required", "reason": "Requires authorized test accounts and operator-defined expectations."},
    {"id": "access_control", "name": "Access Control", "status": "Manual Review Required", "reason": "Requires paired authorized identities and objects."},
    {"id": "api_security", "name": "API Security Inventory", "status": "Planned", "reason": "OpenAPI import and endpoint inventory are not implemented yet."},
    {"id": "client_side", "name": "Client-side Security", "status": "Planned", "reason": "Static source analysis is not implemented yet."},
    {"id": "ssrf", "name": "SSRF Risk Review", "status": "Manual Review Required", "reason": "No active SSRF payloads or internal destination requests are performed."},
    {"id": "file_upload", "name": "File Upload and Path Handling", "status": "Manual Review Required", "reason": "Needs app-specific safe test files and authorized routes."},
    {"id": "information_disclosure", "name": "Information Disclosure", "status": "Planned", "reason": "Only response-banner observations are currently implemented in HTTP/TLS scanner."},
    {"id": "dependency_audit", "name": "Dependency and CVE Analysis", "status": "Planned", "reason": "SBOM parsing and trusted CVE source synchronization are not implemented yet."},
    {"id": "business_logic", "name": "Business Logic Review", "status": "Manual Review Required", "reason": "Guided human review only; no real transactions are executed."},
]
