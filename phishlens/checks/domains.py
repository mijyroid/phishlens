"""Domain helpers: registrable domains, brand impersonation, and lookalike detection."""

from __future__ import annotations

import ipaddress
import re

# Two-level public suffixes common enough to matter for registrable-domain logic.
_MULTI_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "co.jp",
    "co.in",
    "com.br",
    "com.mx",
    "co.nz",
    "com.cn",
    "com.tr",
    "co.za",
    "com.sg",
}

# Brands commonly impersonated in phishing, mapped to the domains they really send from.
BRANDS: dict[str, dict[str, list[str]]] = {
    "paypal": {"names": ["paypal"], "domains": ["paypal.com"]},
    "apple": {"names": ["apple", "icloud", "itunes"], "domains": ["apple.com", "icloud.com", "me.com"]},
    "microsoft": {
        "names": ["microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint"],
        "domains": [
            "microsoft.com",
            "office.com",
            "outlook.com",
            "live.com",
            "microsoftonline.com",
            "sharepoint.com",
            "onedrive.com",
        ],
    },
    "google": {"names": ["google", "gmail"], "domains": ["google.com", "gmail.com", "youtube.com"]},
    "amazon": {"names": ["amazon", "aws"], "domains": ["amazon.com", "amazon.co.uk", "amazonaws.com"]},
    "netflix": {"names": ["netflix"], "domains": ["netflix.com"]},
    "chase": {"names": ["chase", "jpmorgan"], "domains": ["chase.com", "jpmorgan.com", "jpmchase.com"]},
    "bankofamerica": {"names": ["bank of america", "bofa"], "domains": ["bankofamerica.com", "bofa.com"]},
    "wellsfargo": {"names": ["wells fargo"], "domains": ["wellsfargo.com"]},
    "citi": {"names": ["citi", "citibank"], "domains": ["citi.com", "citibank.com"]},
    "docusign": {"names": ["docusign"], "domains": ["docusign.com", "docusign.net"]},
    "dropbox": {"names": ["dropbox"], "domains": ["dropbox.com"]},
    "linkedin": {"names": ["linkedin"], "domains": ["linkedin.com"]},
    "facebook": {"names": ["facebook", "meta"], "domains": ["facebook.com", "facebookmail.com", "meta.com"]},
    "instagram": {"names": ["instagram"], "domains": ["instagram.com"]},
    "coinbase": {"names": ["coinbase"], "domains": ["coinbase.com"]},
    "venmo": {"names": ["venmo"], "domains": ["venmo.com"]},
    "usps": {"names": ["usps", "postal service"], "domains": ["usps.com", "usps.gov"]},
    "fedex": {"names": ["fedex"], "domains": ["fedex.com"]},
    "ups": {"names": ["ups"], "domains": ["ups.com"]},
    "dhl": {"names": ["dhl"], "domains": ["dhl.com"]},
    "irs": {"names": ["irs", "internal revenue service"], "domains": ["irs.gov"]},
    "fidelity": {"names": ["fidelity"], "domains": ["fidelity.com"]},
    "vanguard": {"names": ["vanguard"], "domains": ["vanguard.com"]},
    "utdallas": {"names": ["ut dallas", "utdallas", "utd"], "domains": ["utdallas.edu"]},
}

FREE_MAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "aol.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.com",
    "yandex.com",
    "zoho.com",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "t.ly",
    "tiny.cc",
    "s.id",
    "v.gd",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "xyz",
    "top",
    "click",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "icu",
    "cam",
    "rest",
    "buzz",
    "monster",
    "cyou",
    "sbs",
    "quest",
    "support",
    "live",
}

_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("7", "t")]


def registrable_domain(host: str | None) -> str | None:
    """Best-effort eTLD+1, e.g. 'login.secure.paypal.co.uk' -> 'paypal.co.uk'."""
    if not host:
        return None
    host = host.lower().strip(".")
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) < 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _core_label(domain: str) -> str:
    """'paypal-secure.co.uk' -> 'paypal-secure'."""
    return domain.split(".")[0]


def _normalize(label: str) -> str:
    label = label.lower()
    for fake, real in _HOMOGLYPHS:
        label = label.replace(fake, real)
    return label


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_official_domain(domain: str | None, brand: str) -> bool:
    reg = registrable_domain(domain)
    return bool(reg) and reg in BRANDS[brand]["domains"]


def brand_in_text(text: str | None) -> str | None:
    """Return the brand key if a brand name appears as a whole word in text."""
    if not text:
        return None
    lowered = text.lower()
    for brand, info in BRANDS.items():
        for name in info["names"]:
            if re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", lowered):
                return brand
    return None


def lookalike_brand(host: str | None) -> tuple[str, str] | None:
    """Detect a domain imitating a brand. Returns (brand, reason) or None.

    Catches typosquats (paypa1.com, arnazon.com), brand-plus-word domains
    (paypal-secure-login.com), and brand names used as subdomains of an
    unrelated domain (paypal.com.account-verify.ru).
    """
    if not host:
        return None
    host = host.lower().strip(".")
    reg = registrable_domain(host)
    if not reg or is_ip(host):
        return None
    if any(reg in info["domains"] for info in BRANDS.values()):
        return None  # it's the real thing

    core = _core_label(reg)
    tokens = [t for t in re.split(r"[-_\d]+", core) if t]
    subdomain_labels = host[: -len(reg)].strip(".").split(".") if host != reg else []

    for brand, info in BRANDS.items():
        # Compare against the brand's primary domain only; secondary domains like
        # live.com or me.com are generic words and would cause false positives.
        official = _core_label(info["domains"][0])
        if core == official:
            return brand, f"'{reg}' uses the name {official} but is not one of its real domains"
        if len(official) >= 5:
            if _normalize(core) == official:
                return brand, f"'{reg}' swaps look-alike characters to imitate {official}"
            if len(core) >= 4 and _levenshtein(core, official) <= (1 if len(official) < 7 else 2):
                return brand, f"'{reg}' is one or two letters away from {official}"
        if official in tokens and (len(official) >= 5 or len(tokens) > 1):
            return brand, f"'{reg}' combines the brand name '{official}' with other words"
        if len(official) >= 4 and official in subdomain_labels:
            return brand, f"'{host}' puts '{official}' in a subdomain of unrelated domain '{reg}'"
    return None
