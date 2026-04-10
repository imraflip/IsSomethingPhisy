from pydantic_settings import BaseSettings


class ScannerConfig(BaseSettings):
    # score threshold — URL is "phishy" if score >= this
    PHISHY_THRESHOLD: int = 50

    # url length limit before we flag it
    URL_LENGTH_THRESHOLD: int = 75

    # how many subdomains before it's suspicious
    EXCESSIVE_SUBDOMAIN_COUNT: int = 3

    SUSPICIOUS_TLDS: list[str] = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".xyz",
        ".top",
        ".buzz",
        ".gq",
    ]

    SUSPICIOUS_KEYWORDS: list[str] = [
        "paypal",
        "netflix",
        "instagram",
        "facebook",
        "login",
        "verify",
        "secure",
        "bank",
        "account",
        "update",
        "confirm",
        "signin",
        "password",
        "credential",
    ]

    URL_SHORTENERS: list[str] = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "short.io",
        "cutt.ly",
    ]

    # rule weights
    WEIGHT_URL_LENGTH: int = 10
    WEIGHT_IP_ADDRESS: int = 25
    WEIGHT_EXCESSIVE_SUBDOMAINS: int = 15
    WEIGHT_AT_SYMBOL: int = 25
    WEIGHT_SUSPICIOUS_KEYWORDS: int = 15
    WEIGHT_SUSPICIOUS_TLD: int = 20
    WEIGHT_URL_SHORTENER: int = 15
    WEIGHT_PUNYCODE_HOMOGRAPH: int = 25
    WEIGHT_NO_HTTPS: int = 10

    model_config = {"env_prefix": "PHISY_"}


settings = ScannerConfig()
