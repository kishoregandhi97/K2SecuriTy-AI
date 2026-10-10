from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from fastapi import HTTPException


def normalize_host(host: str) -> str:
    if not host or any(ch in host for ch in "/\\@%\x00"):
        raise ValueError("Invalid hostname")
    try:
        normalized = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid IDNA hostname") from exc
    if len(normalized) > 253 or not normalized:
        raise ValueError("Invalid hostname length")
    labels = normalized.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") or
           not all(c.isalnum() or c == "-" for c in label) for label in labels):
        raise ValueError("Invalid hostname format")
    return normalized


def parse_target_url(url: str) -> tuple[str, int, str]:
    try:
        parsed = urlsplit(url.strip())
        if parsed.scheme.lower() != "https":
            raise ValueError("Only HTTPS targets are enabled in this build")
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("URL must have a hostname and no embedded credentials")
        host = normalize_host(parsed.hostname)
        port = parsed.port or 443
        if port != 443:
            raise ValueError("Only port 443 is enabled by default")
        if parsed.fragment:
            # Fragments are client-side and are not sent in HTTP requests.
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        return host, port, url
    except (ValueError, UnicodeError) as exc:
        raise ValueError(str(exc)) from exc


def redact_url(url: str) -> str:
    """Keep URL shape while removing query values from stored evidence and findings."""
    parsed = urlsplit(url)
    safe_query = urlencode([(key, "[REDACTED]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, safe_query, ""))

def is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    return ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local or
                                  ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def resolve_public(host: str, port: int = 443) -> list[str]:
    try:
        # Literal IPs are checked directly; hostnames are resolved once and the resulting
        # addresses are pinned into the HTTP client's resolver for the connection.
        try:
            ip = ipaddress.ip_address(host)
            values = [str(ip)]
        except ValueError:
            values = sorted({item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
        if not values or any(not is_public_ip(value) for value in values):
            raise ValueError("Target resolves to a prohibited non-public IP address")
        return values
    except (OSError, ValueError) as exc:
        raise ValueError(f"DNS/address validation failed: {exc}") from exc


def require_target_scope(url: str, registered_host: str, authorized: bool,
                         global_allowlist: tuple[str, ...] = ()) -> tuple[str, int, str, list[str]]:
    if not authorized:
        raise ValueError("Target is not marked authorized")
    host, port, clean_url = parse_target_url(url)
    root = normalize_host(registered_host)
    if host != root:
        raise ValueError("Exact-host scope required; target hostname must match registered hostname")
    if global_allowlist and host not in global_allowlist:
        raise ValueError("Target hostname is not in ALLOWED_HOSTS")
    addresses = resolve_public(host, port)
    return host, port, clean_url, addresses
