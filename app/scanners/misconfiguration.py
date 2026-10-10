from __future__ import annotations
import asyncio, ssl, socket, hashlib
from urllib.parse import urlsplit, urlunsplit
import aiohttp
from app.scanners.base import Scanner, Finding, ScanContext
from app.scanners.http_tls import PinnedResolver
from app.services.scope import is_public_ip, resolve_public

class MisconfigurationScanner(Scanner):
    scanner_id = "misconfiguration"
    display_name = "Security Misconfiguration (metadata endpoints)"
    version = "1.0.0"
    categories = ("security-misconfiguration", "information-disclosure")
    mode = "passive"
    limitations = "Checks four common API-schema locations; a public schema is informational and requires context review. No backup-file or admin brute-force probing."
    paths = ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api-docs")

    async def run(self, context: ScanContext) -> list[Finding]:
        parsed = urlsplit(context.target_url)
        origin = urlunsplit(("https", context.hostname, "", "", ""))
        findings: list[Finding] = []
        for path in self.paths[:min(len(self.paths), context.request_budget)]:
            addresses = resolve_public(context.hostname, 443)
            if set(addresses) != set(context.pinned_addresses):
                raise ValueError("DNS answer changed during assessment; request blocked")
            connector = aiohttp.TCPConnector(resolver=PinnedResolver(context.hostname, context.pinned_addresses),
                                             ssl=ssl.create_default_context(), limit=1, use_dns_cache=False)
            timeout = aiohttp.ClientTimeout(total=context.timeout_seconds, connect=min(4, context.timeout_seconds))
            try:
                async with aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=False,
                    headers={"User-Agent":"K2SecuriTy-AI/0.1 (authorized passive assessment)", "Accept":"application/json,text/plain;q=0.8,*/*;q=0.2"}) as session:
                    async with session.get(origin + path, allow_redirects=False) as response:
                        status = response.status
                        content_type = response.headers.get("Content-Type", "")[:160]
                        raw = await response.content.read(min(context.max_response_bytes, 12000))
                        excerpt = raw.decode("utf-8", errors="replace")
                        if status != 200 or "json" not in content_type.lower():
                            continue
                        # A generic SPA fallback can return 200. Require recognizable schema structure.
                        lower = excerpt.lower()
                        schema_markers = ('"openapi"', '"swagger"', '"paths"')
                        if not any(marker in lower for marker in schema_markers):
                            continue
                        findings.append(Finding(
                            title="API schema document publicly accessible",
                            category="information-disclosure",
                            severity="Informational",
                            confidence="High",
                            status="Needs Manual Verification",
                            url=origin + path,
                            description="A recognizable API schema document was returned without authentication in this unauthenticated passive request. Public schemas are not inherently a vulnerability; review whether this exposure is intended and whether the schema discloses sensitive internal operations or details.",
                            evidence={"http_status": status, "content_type": content_type,
                                      "schema_markers": [m for m in schema_markers if m in lower],
                                      "response_sample_sha256": hashlib.sha256(raw).hexdigest(),
                                      "response_sample_bytes": len(raw),
                                      "body_truncated": len(raw) >= min(context.max_response_bytes, 12000),
                                      "response_body_stored": False},
                            remediation="If the schema is intended to be private, require appropriate authentication and authorization. Remove secrets and internal-only details from published schemas; do not rely on obscurity.",
                            references=["https://owasp.org/www-project-api-security/", "https://cheatsheetseries.owasp.org/"],
                            scanner_id=self.scanner_id))
            except (aiohttp.ClientError, asyncio.TimeoutError, ssl.SSLError) as exc:
                # A single optional metadata path failing should not abort the whole assessment.
                continue
        return findings
