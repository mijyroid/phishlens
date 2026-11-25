"""Link analysis: deceptive link text, risky hosts, and credential-harvesting forms."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from phishlens.checks.domains import (
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    is_ip,
    lookalike_brand,
    registrable_domain,
)
from phishlens.models import Category, Finding, LinkInfo, Severity
from phishlens.parser import RawLink

MAX_LINKS = 100

# Flag -> (severity, finding title, detail template). {domain} is filled in per link.
_FLAG_INFO: dict[str, tuple[Severity, str, str]] = {
    "text_mismatch": (
        Severity.HIGH,
        "Link text hides where the link really goes",
        "A link displays one address but actually opens {domain}.",
    ),
    "ip_host": (
        Severity.HIGH,
        "Link points to a raw IP address",
        "Legitimate companies link to their domain name, not a bare IP address ({domain}).",
    ),
    "userinfo_trick": (
        Severity.HIGH,
        "Link uses an '@' to disguise its destination",
        "Everything before the '@' in a URL is ignored by the browser; the real destination is {domain}.",
    ),
    "lookalike": (
        Severity.HIGH,
        "Link goes to a look-alike domain",
        "{reason}.",
    ),
    "punycode": (
        Severity.HIGH,
        "Link uses an encoded international domain",
        "{domain} uses punycode, which can render as characters that look like a real brand.",
    ),
    "dangerous_scheme": (
        Severity.HIGH,
        "Link runs code or embeds data instead of opening a page",
        "javascript: and data: links can run scripts or show fake login pages.",
    ),
    "form": (
        Severity.HIGH,
        "Email contains a form",
        "Real companies don't ask you to type information into a form inside an email. This one submits to {domain}.",
    ),
    "shortener": (
        Severity.MEDIUM,
        "Link uses a URL shortener",
        "Shortened links ({domain}) hide the real destination until you click.",
    ),
    "suspicious_tld": (
        Severity.LOW,
        "Link uses a top-level domain popular with scammers",
        "{domain} ends in a domain extension that is cheap and frequently abused.",
    ),
    "http": (
        Severity.LOW,
        "Link isn't encrypted",
        "The link to {domain} uses http instead of https.",
    ),
    "many_subdomains": (
        Severity.LOW,
        "Link has an unusually long chain of subdomains",
        "{domain} stacks many subdomains, a trick for pushing the real domain out of view.",
    ),
}

_DOMAIN_IN_TEXT = re.compile(r"(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")
_LIKELY_TLDS = {
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "io",
    "co",
    "us",
    "uk",
    "ca",
    "au",
    "de",
    "fr",
    "in",
    "jp",
    "cn",
    "ru",
    "br",
    "mx",
    "info",
    "biz",
    "me",
    "app",
    "dev",
    "ai",
    "ly",
    "gl",
    "ws",
    "tv",
    "cc",
    "xyz",
    "top",
    "online",
    "site",
    "shop",
    "store",
} | SUSPICIOUS_TLDS


def _host(url: str) -> tuple[str | None, str]:
    """Return (hostname, scheme) for a URL, tolerating scheme-less 'www.' links."""
    candidate = url.strip()
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None, ""
    return (parts.hostname.lower() if parts.hostname else None), parts.scheme.lower()


def analyze_links(raw_links: list[RawLink]) -> tuple[list[LinkInfo], list[Finding]]:
    links: list[LinkInfo] = []
    findings: list[Finding] = []
    seen_findings: set[tuple[str, str]] = set()

    def add(flag: str, domain: str, evidence: str, reason: str = "") -> None:
        # Report low-severity flags once per email; serious ones once per domain.
        key = (flag, "" if _FLAG_INFO[flag][0] == Severity.LOW else domain)
        if key in seen_findings:
            return
        seen_findings.add(key)
        severity, title, template = _FLAG_INFO[flag]
        findings.append(
            Finding(
                rule=f"link_{flag}",
                category=Category.LINKS,
                severity=severity,
                title=title,
                detail=template.format(domain=domain or "an unknown host", reason=reason),
                evidence=evidence[:300],
            )
        )

    for raw in raw_links[:MAX_LINKS]:
        host, scheme = _host(raw.url)
        info = LinkInfo(url=raw.url, text=raw.text, domain=host)

        if raw.source == "form":
            info.flags.append("form")
            add("form", host or "an unspecified address", raw.url)

        if scheme in ("javascript", "data", "vbscript"):
            info.flags.append("dangerous_scheme")
            add("dangerous_scheme", scheme, raw.url[:80])
            links.append(info)
            continue
        if scheme in ("mailto", "tel", "cid", "") and raw.source != "form" and not raw.url.lower().startswith("www."):
            links.append(info)
            continue
        if not host:
            links.append(info)
            continue

        reg = registrable_domain(host)
        authority = raw.url.split("//", 1)[-1].split("/", 1)[0]

        if "@" in authority:
            info.flags.append("userinfo_trick")
            add("userinfo_trick", host, raw.url)
        if is_ip(host):
            info.flags.append("ip_host")
            add("ip_host", host, raw.url)
        if any(label.startswith("xn--") for label in host.split(".")):
            info.flags.append("punycode")
            add("punycode", host, raw.url)
        look = lookalike_brand(host)
        if look:
            info.flags.append("lookalike")
            add("lookalike", host, raw.url, reason=look[1])
        if reg in URL_SHORTENERS:
            info.flags.append("shortener")
            add("shortener", reg, raw.url)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            info.flags.append("suspicious_tld")
            add("suspicious_tld", host, raw.url)
        if scheme == "http":
            info.flags.append("http")
            add("http", host, raw.url)
        if reg and host != reg and len(host[: -len(reg)].strip(".").split(".")) >= 4:
            info.flags.append("many_subdomains")
            add("many_subdomains", host, raw.url)

        # Visible text names a different domain than the real target.
        if raw.text:
            for shown in _DOMAIN_IN_TEXT.findall(raw.text):
                if shown.rsplit(".", 1)[-1].lower() not in _LIKELY_TLDS:
                    continue  # e.g. "invoice.pdf" isn't a web address
                shown_reg = registrable_domain(shown.lower())
                if shown_reg and reg and shown_reg != reg:
                    info.flags.append("text_mismatch")
                    add("text_mismatch", host, f"Shows '{raw.text[:80]}' → opens {raw.url}")
                    break

        links.append(info)
    return links, findings
