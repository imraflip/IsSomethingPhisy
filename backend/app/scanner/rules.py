from app.config import ScannerConfig
from app.scanner.schemas import RuleResult
from app.utils.url_parser import ParsedUrl


def check_url_length(parsed: ParsedUrl, config: ScannerConfig) -> RuleResult:
    """Unusually long URLs can hide the real destination."""
    length = len(parsed.raw_url)
    triggered = length > config.URL_LENGTH_THRESHOLD
    return RuleResult(
        name="url_length",
        triggered=triggered,
        weight=config.WEIGHT_URL_LENGTH,
        score_contribution=config.WEIGHT_URL_LENGTH if triggered else 0,
        explanation=(
            f"The URL is {length} characters long, which exceeds the "
            f"{config.URL_LENGTH_THRESHOLD}-character threshold. "
            "Excessively long URLs are often used to hide the real destination."
            if triggered
            else f"The URL length ({length} chars) is within normal range."
        ),
    )


def check_ip_address(parsed: ParsedUrl, config: ScannerConfig) -> RuleResult:
    """Legit sites almost never use raw IPs."""
    triggered = parsed.is_ip
    return RuleResult(
        name="ip_address",
        triggered=triggered,
        weight=config.WEIGHT_IP_ADDRESS,
        score_contribution=config.WEIGHT_IP_ADDRESS if triggered else 0,
        explanation=(
            "The URL uses a raw IP address instead of a domain name. "
            "Legitimate websites almost always use domain names."
            if triggered
            else "The URL uses a domain name, not a raw IP address."
        ),
    )


def check_excessive_subdomains(parsed: ParsedUrl, config: ScannerConfig) -> RuleResult:
    """Too many subdomains is a red flag (e.g. secure.login.paypal.evil.com)."""
    count = len(parsed.subdomains)
    triggered = count >= config.EXCESSIVE_SUBDOMAIN_COUNT
    return RuleResult(
        name="excessive_subdomains",
        triggered=triggered,
        weight=config.WEIGHT_EXCESSIVE_SUBDOMAINS,
        score_contribution=config.WEIGHT_EXCESSIVE_SUBDOMAINS if triggered else 0,
        explanation=(
            f"The URL has {count} subdomains, which is unusually high. "
            "Phishing sites often use many subdomains to mimic legitimate domains "
            "(e.g. secure.login.paypal.evil.com)."
            if triggered
            else f"The subdomain count ({count}) is normal."
        ),
    )


def check_at_symbol(parsed: ParsedUrl, config: ScannerConfig) -> RuleResult:
    """@ in a URL is almost always malicious — browsers ignore everything before it."""
    triggered = parsed.has_at_symbol
    return RuleResult(
        name="at_symbol",
        triggered=triggered,
        weight=config.WEIGHT_AT_SYMBOL,
        score_contribution=config.WEIGHT_AT_SYMBOL if triggered else 0,
        explanation=(
            "The URL contains an '@' symbol, which can be used to disguise the real destination. "
            "Browsers ignore everything before '@' in a URL, so 'http://google.com@evil.com' "
            "actually visits evil.com."
            if triggered
            else "No '@' symbol found in the URL."
        ),
    )


def check_suspicious_keywords(parsed: ParsedUrl, config: ScannerConfig) -> RuleResult:
    """Look for phishing-y keywords like 'paypal', 'login', etc. in subdomain and path."""
    lower_subdomain = parsed.subdomain.lower()
    lower_path = parsed.path.lower()
    search_text = lower_subdomain + lower_path

    found = [kw for kw in config.SUSPICIOUS_KEYWORDS if kw in search_text]
    triggered = len(found) > 0

    return RuleResult(
        name="suspicious_keywords",
        triggered=triggered,
        weight=config.WEIGHT_SUSPICIOUS_KEYWORDS,
        score_contribution=config.WEIGHT_SUSPICIOUS_KEYWORDS if triggered else 0,
        explanation=(
            f"Found suspicious keyword(s) in the URL: {', '.join(found)}. "
            "These words are commonly used in phishing URLs to mimic legitimate services."
            if triggered
            else "No suspicious keywords detected in the URL."
        ),
    )


def check_suspicious_tld(parsed: ParsedUrl, config: ScannerConfig) -> RuleResult:
    """TLDs like .tk, .ml, .ga are heavily abused for phishing."""
    tld = f".{parsed.suffix}" if parsed.suffix else ""
    triggered = tld.lower() in [t.lower() for t in config.SUSPICIOUS_TLDS]
    return RuleResult(
        name="suspicious_tld",
        triggered=triggered,
        weight=config.WEIGHT_SUSPICIOUS_TLD,
        score_contribution=config.WEIGHT_SUSPICIOUS_TLD if triggered else 0,
        explanation=(
            f"The domain uses {tld}, a TLD commonly associated with free disposable domains "
            "used in phishing campaigns."
            if triggered
            else f"The TLD ({tld}) is not on the suspicious list."
        ),
    )


def check_url_shortener(parsed: ParsedUrl, config: ScannerConfig) -> RuleResult:
    """Shortened URLs hide the real destination."""
    domain = parsed.registered_domain.lower()
    # Also check netloc without port for shorteners.
    triggered = domain in [s.lower() for s in config.URL_SHORTENERS]
    return RuleResult(
        name="url_shortener",
        triggered=triggered,
        weight=config.WEIGHT_URL_SHORTENER,
        score_contribution=config.WEIGHT_URL_SHORTENER if triggered else 0,
        explanation=(
            f"The URL uses a known URL shortening service ({domain}). "
            "Shortened URLs hide the real destination and are often used in phishing."
            if triggered
            else "The URL does not use a known URL shortener."
        ),
    )


def check_punycode_homograph(parsed: ParsedUrl, config: ScannerConfig) -> RuleResult:
    """IDN homograph attack — e.g. using cyrillic 'а' instead of latin 'a'."""
    domain_to_check = parsed.netloc.split(":")[0]  # strip port

    # Check for punycode-encoded domains (xn--).
    has_punycode = "xn--" in domain_to_check.lower()

    # Check for non-ASCII characters (could be Unicode homoglyphs).
    has_non_ascii = not all(ord(c) < 128 for c in domain_to_check)

    triggered = has_punycode or has_non_ascii
    return RuleResult(
        name="punycode_homograph",
        triggered=triggered,
        weight=config.WEIGHT_PUNYCODE_HOMOGRAPH,
        score_contribution=config.WEIGHT_PUNYCODE_HOMOGRAPH if triggered else 0,
        explanation=(
            "The domain contains non-ASCII or punycode-encoded characters. "
            "This is a common technique (IDN homograph attack) where characters from different "
            "scripts are used to mimic legitimate domain names "
            "(e.g. 'paypal.com' using Cyrillic 'a')."
            if triggered
            else "The domain uses only standard ASCII characters."
        ),
    )


def check_no_https(parsed: ParsedUrl, config: ScannerConfig) -> RuleResult:
    """Not conclusive on its own, but most legit sites use HTTPS these days."""
    triggered = parsed.scheme.lower() != "https"
    return RuleResult(
        name="no_https",
        triggered=triggered,
        weight=config.WEIGHT_NO_HTTPS,
        score_contribution=config.WEIGHT_NO_HTTPS if triggered else 0,
        explanation=(
            "The URL does not use HTTPS. While not conclusive on its own, most legitimate "
            "websites use HTTPS for secure communication."
            if triggered
            else "The URL uses HTTPS."
        ),
    )


# Registry of all rules. The engine iterates over this list.
ALL_RULES = [
    check_url_length,
    check_ip_address,
    check_excessive_subdomains,
    check_at_symbol,
    check_suspicious_keywords,
    check_suspicious_tld,
    check_url_shortener,
    check_punycode_homograph,
    check_no_https,
]
