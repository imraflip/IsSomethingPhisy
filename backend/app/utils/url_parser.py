from dataclasses import dataclass, field
from urllib.parse import urlparse

import tldextract


@dataclass(frozen=True)
class ParsedUrl:
    raw_url: str
    scheme: str
    netloc: str
    path: str
    query: str
    fragment: str
    domain: str
    suffix: str  # tld like "com", "co.uk"
    registered_domain: str  # e.g. "example.com"
    subdomain: str
    subdomains: list[str] = field(default_factory=list)
    port: str = ""
    has_at_symbol: bool = False
    is_ip: bool = False


def normalize_url(raw: str) -> str:
    """If someone pastes 'example.com' without a scheme, prepend https://"""
    stripped = raw.strip()
    if not stripped:
        return stripped
    if "://" not in stripped:
        stripped = "https://" + stripped
    return stripped


def parse_url(raw_url: str) -> ParsedUrl:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    hostname = parsed.hostname or ""
    is_ip = _is_ip_address(hostname)

    subdomain = extracted.subdomain
    subdomain_parts = [s for s in subdomain.split(".") if s] if subdomain else []

    has_at = "@" in (parsed.netloc or "")

    return ParsedUrl(
        raw_url=url,
        scheme=parsed.scheme,
        netloc=parsed.netloc or "",
        path=parsed.path or "",
        query=parsed.query or "",
        fragment=parsed.fragment or "",
        domain=extracted.domain,
        suffix=extracted.suffix,
        registered_domain=extracted.top_domain_under_public_suffix,
        subdomain=subdomain,
        subdomains=subdomain_parts,
        port=str(parsed.port) if parsed.port else "",
        has_at_symbol=has_at,
        is_ip=is_ip,
    )


def _is_ip_address(hostname: str) -> bool:
    # ipv6 in brackets
    if hostname.startswith("[") and hostname.endswith("]"):
        return True
    # ipv4
    parts = hostname.split(".")
    if len(parts) == 4:
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    return False
