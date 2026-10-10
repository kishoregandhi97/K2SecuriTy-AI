from __future__ import annotations
import asyncio
import ssl
import socket
import hashlib
from datetime import datetime, timezone
from datetime import timedelta
from urllib.parse import urljoin, urlsplit
import aiohttp
from app.scanners.base import Scanner, Finding, ScanContext
from app.services.scope import is_public_ip, parse_target_url, resolve_public, redact_url

def probe_certificate(host: str, addresses: list[str], timeout_seconds: float) -> dict:
    """Verify TLS chain and hostname against a pinned public IP; return metadata only."""
    last_error = "unknown"
    expiry_iso = None
    days_left = None
    for address in addresses[:2]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((address, 443), timeout=timeout_seconds) as raw:
                with context.wrap_socket(raw, server_hostname=host) as wrapped:
                    cert = wrapped.getpeercert()
                    expiry = ssl.cert_time_to_seconds(cert["notAfter"])
                    expiry_dt = datetime.fromtimestamp(expiry, timezone.utc)
                    days_left = int((expiry_dt - datetime.now(timezone.utc)).total_seconds() // 86400)
                    expiry_iso = expiry_dt.isoformat()
                    return {"verified": True, "hostname_verified": True, "chain_verified": True,
                            "expires_at": expiry_iso, "days_until_expiry": days_left}
        except (ssl.SSLError, OSError, KeyError, ValueError) as exc:
            last_error = type(exc).__name__
            # Inspect expiry metadata without trusting the certificate. This connection sends
            # no HTTP request and never transmits credentials; the result remains unverified.
            try:
                unverified = ssl._create_unverified_context()
                with socket.create_connection((address, 443), timeout=timeout_seconds) as raw:
                    with unverified.wrap_socket(raw, server_hostname=host) as wrapped:
                        cert = wrapped.getpeercert()
                        if cert and cert.get("notAfter"):
                            expiry_dt = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
                            expiry_iso = expiry_dt.isoformat()
                            days_left = int((expiry_dt - datetime.now(timezone.utc)).total_seconds() // 86400)
            except (ssl.SSLError, OSError, KeyError, ValueError):
                pass
    return {"verified": False, "hostname_verified": False, "chain_verified": False,
            "validation_error": last_error, "expires_at": expiry_iso, "days_until_expiry": days_left}

class PinnedResolver(aiohttp.abc.AbstractResolver):
    """Resolver that returns only addresses approved before connecting."""
    def __init__(self, hostname: str, addresses: list[str]):
        self.hostname = hostname.lower().rstrip(".")
        self.addresses = addresses

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        if host.lower().rstrip(".") != self.hostname:
            raise OSError("Connection hostname changed; blocked")
        records = []
        for address in self.addresses:
            if not is_public_ip(address):
                raise OSError("Prohibited IP address")
            ip = socket.inet_pton(socket.AF_INET6 if ":" in address else socket.AF_INET, address)
            records.append({"hostname": host, "host": address, "port": port,
                            "family": socket.AF_INET6 if ":" in address else socket.AF_INET,
                            "proto": 0, "flags": 0})
        return records

    async def close(self):
        return None

class HttpTlsScanner(Scanner):
    scanner_id = "http_tls"
    display_name = "HTTP and TLS Configuration"
    version = "1.0.0"
    categories = ("security-misconfiguration", "transport-security")
    limitations = "Passive HTTP response checks and certificate validation; not a full TLS protocol enumerator."

    async def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        cert = await asyncio.to_thread(probe_certificate, context.hostname, context.pinned_addresses, context.timeout_seconds)
        if not cert["verified"]:
            findings.append(Finding("TLS certificate validation failed", "transport-security", "Medium", "High", "Potential",
                redact_url(context.target_url), "A TLS handshake did not pass certificate chain and hostname validation. The scanner stopped before making an HTTP request.",
                {"certificate_validation": cert, "http_request_sent": False},
                "Install a valid certificate for the exact hostname, include the required intermediate chain, and renew expired certificates. Do not disable certificate validation.",
                ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"], self.scanner_id))
            return findings
        if cert.get("days_until_expiry") is not None and cert["days_until_expiry"] <= 30:
            findings.append(Finding("TLS certificate expires soon", "transport-security", "Low", "High", "Potential",
                redact_url(context.target_url), "The verified TLS certificate expires within 30 days.",
                {"certificate_validation": cert}, "Renew the certificate before its expiry date and verify automated renewal.",
                ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"], self.scanner_id))
        current = context.target_url
        redirects = 0
        response_status = None
        response_headers: dict[str, str] = {}
        body_sample_hash = ""
        body_sample_size = 0
        body_sample_truncated = False
        final_url = current
        while True:
            host, port, normalized = parse_target_url(current)
            if host != context.hostname:
                raise ValueError("Redirect left the exact registered hostname scope")
            addresses = resolve_public(host, port)
            # Requiring equality with the original pinned address set protects against a
            # DNS answer changing between scope check and the actual request.
            if set(addresses) != set(context.pinned_addresses):
                raise ValueError("DNS answer changed during assessment; request blocked")
            resolver = PinnedResolver(host, context.pinned_addresses)
            connector = aiohttp.TCPConnector(resolver=resolver, ssl=ssl.create_default_context(),
                                             limit=1, use_dns_cache=False)
            timeout = aiohttp.ClientTimeout(total=context.timeout_seconds, connect=min(4, context.timeout_seconds))
            try:
                async with aiohttp.ClientSession(connector=connector, timeout=timeout,
                    trust_env=False, headers={"User-Agent": "K2SecuriTy-AI/0.1 (authorized passive assessment)",
                    "Range": f"bytes=0-{max(0, context.max_response_bytes-1)}"}) as session:
                    async with session.get(current, allow_redirects=False) as response:
                        response_status = response.status
                        response_headers = {k.lower(): v[:1000] for k, v in response.headers.items()}
                        raw = await response.content.read(context.max_response_bytes)
                        body_sample_hash = hashlib.sha256(raw).hexdigest()
                        body_sample_size = len(raw)
                        body_sample_truncated = len(raw) >= context.max_response_bytes
                        if response.status in (301, 302, 303, 307, 308) and response.headers.get("Location"):
                            if redirects >= 3:
                                raise ValueError("Redirect limit reached")
                            next_url = urljoin(current, response.headers["Location"])
                            next_host, _, next_normalized = parse_target_url(next_url)
                            if next_host != context.hostname:
                                raise ValueError("Cross-host redirect blocked by scope policy")
                            current = next_normalized
                            redirects += 1
                            continue
                        final_url = current
                        break
            except (aiohttp.ClientError, asyncio.TimeoutError, ssl.SSLError) as exc:
                raise RuntimeError(f"HTTP request failed: {type(exc).__name__}") from exc

        safe_final_url = redact_url(final_url)
        common = {"http_status": response_status, "observed_at": datetime.now(timezone.utc).isoformat(),
                  "certificate_validation": cert, "headers_captured": True, "response_sample_sha256": body_sample_hash,
                  "response_sample_bytes": body_sample_size, "response_sample_truncated": body_sample_truncated,
                  "response_body_stored": False}
        header_checks = [
            ("strict-transport-security", "HSTS header absent", "Missing HSTS is a hardening observation; assess HTTPS coverage and application context.", "Low"),
            ("content-security-policy", "Content Security Policy absent", "No CSP header was observed. This alone does not prove XSS.", "Low"),
            ("x-content-type-options", "MIME sniffing protection absent", "X-Content-Type-Options was not observed.", "Low"),
            ("referrer-policy", "Referrer Policy absent", "No Referrer-Policy header was observed.", "Info"),
            ("permissions-policy", "Permissions Policy absent", "No Permissions-Policy header was observed.", "Info"),
        ]
        for key, title, description, severity in header_checks:
            if key not in response_headers:
                findings.append(Finding(title, "security-misconfiguration", severity, "High", "Potential",
                    safe_final_url, description, {**common, "header": key, "present": False},
                    f"Review whether {key} is appropriate for this application and configure it at the application or reverse-proxy layer.",
                    ["https://owasp.org/www-project-web-security-testing-guide/stable/", "https://cheatsheetseries.owasp.org/"], self.scanner_id))
        for key, title in [("server", "Server banner disclosed"), ("x-powered-by", "Technology banner disclosed")]:
            if key in response_headers:
                findings.append(Finding(title, "information-disclosure", "Informational", "High", "Potential",
                    safe_final_url, "A technology-identifying response header was observed; this is not proof of a vulnerability.",
                    {**common, "header": key, "value": response_headers[key][:200]},
                    "Remove unnecessary version details where practical; prioritize patching over hiding banners.",
                    ["https://owasp.org/www-project-top-ten/"], self.scanner_id))
        set_cookie_values = []
        # aiohttp's CIMultiDictProxy preserves multiple Set-Cookie values via getall.
        # Capture is handled from headers for safe minimal metadata; never store cookie values.
        if any(k == "set-cookie" for k in response_headers):
            for cookie in response_headers.get("set-cookie", "").split("\n"):
                attrs = cookie.lower()
                flags = {"secure": "secure" in attrs, "httponly": "httponly" in attrs,
                         "samesite": "samesite=" in attrs}
                if not flags["secure"] or not flags["httponly"] or not flags["samesite"]:
                    findings.append(Finding("Cookie security attributes need review", "session-management", "Low", "Medium", "Needs Manual Verification",
                        safe_final_url, "At least one Set-Cookie header may lack a recommended security attribute. Cookie values are not stored.",
                        {**common, "cookie_flags": flags, "cookie_value_redacted": True},
                        "Review each session cookie and set Secure, HttpOnly, and an appropriate SameSite policy as applicable.",
                        ["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"], self.scanner_id))
        # Evidence intentionally stores headers allowlisted below and a short, redacted body excerpt only.
        safe_headers = {k: v[:300] for k, v in response_headers.items() if k in {
            "content-type", "content-length", "strict-transport-security", "content-security-policy",
            "x-content-type-options", "referrer-policy", "permissions-policy", "x-frame-options", "server", "x-powered-by"}}
        findings.append(Finding("HTTP response observed", "assessment-observation", "Informational", "High", "Potential",
            safe_final_url, "The target returned an HTTP response; this informational record anchors the assessment evidence.",
            {**common, "safe_response_headers": safe_headers, "response_sample_sha256": body_sample_hash, "response_body_stored": False},
            "No remediation implied by this observation.", ["https://owasp.org/www-project-web-security-testing-guide/stable/"], self.scanner_id))
        return findings
