"""Threat-intelligence lookups for links found in the email.

Both sources are optional: without an API key the check is skipped and the
report says so. Only URLs are sent to these services, never the email itself.
PhishLens never visits the links.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

import httpx

from phishlens.config import Settings
from phishlens.models import Category, Finding, IntelStatus, Severity

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
MAX_SAFE_BROWSING_URLS = 100
MAX_URLHAUS_URLS = 20

# Wording required by Google's Safe Browsing usage guidelines for user warnings.
SAFE_BROWSING_ADVISORY = "Advisory provided by Google"
_SB_THREAT_TEXT = {
    "SOCIAL_ENGINEERING": "a deceptive (phishing) site",
    "MALWARE": "a site that may install malware",
    "UNWANTED_SOFTWARE": "a site that may install unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "a site that may host harmful apps",
}


def web_urls(urls: list[str]) -> list[str]:
    out: list[str] = []
    for url in urls:
        candidate = "http://" + url if url.lower().startswith("www.") else url
        try:
            parts = urlsplit(candidate)
        except ValueError:
            continue
        if parts.scheme in ("http", "https") and parts.hostname and candidate not in out:
            out.append(candidate)
    return out


async def check_safe_browsing(
    client: httpx.AsyncClient, urls: list[str], api_key: str | None
) -> tuple[IntelStatus, list[Finding]]:
    if not api_key:
        return IntelStatus(source="Google Safe Browsing", status="skipped", detail="No API key configured"), []
    if not urls:
        return IntelStatus(source="Google Safe Browsing", status="ok", detail="No links to check"), []
    body = {
        "client": {"clientId": "phishlens", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": list(_SB_THREAT_TEXT),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:MAX_SAFE_BROWSING_URLS]],
        },
    }
    try:
        resp = await client.post(SAFE_BROWSING_URL, params={"key": api_key}, json=body)
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
    except (httpx.HTTPError, ValueError) as exc:
        return IntelStatus(source="Google Safe Browsing", status="error", detail=type(exc).__name__), []

    findings: list[Finding] = []
    seen: set[str] = set()
    for match in matches:
        url = match.get("threat", {}).get("url", "")
        if url in seen:
            continue
        seen.add(url)
        threat = _SB_THREAT_TEXT.get(match.get("threatType", ""), "an unsafe site")
        findings.append(
            Finding(
                rule="safe_browsing_match",
                category=Category.THREAT_INTEL,
                severity=Severity.CRITICAL,
                title="Link is on Google's list of unsafe sites",
                detail=f"This link may lead to {threat}. {SAFE_BROWSING_ADVISORY}. "
                "Safe Browsing isn't perfect, so a clean result doesn't guarantee a link is safe.",
                evidence=url,
            )
        )
    detail = f"Checked {min(len(urls), MAX_SAFE_BROWSING_URLS)} link(s), {len(findings)} flagged"
    return IntelStatus(source="Google Safe Browsing", status="ok", detail=detail), findings


async def _urlhaus_one(client: httpx.AsyncClient, url: str, api_key: str) -> dict | None:
    resp = await client.post(URLHAUS_URL, data={"url": url}, headers={"Auth-Key": api_key})
    resp.raise_for_status()
    data = resp.json()
    return data if data.get("query_status") == "ok" else None


async def check_urlhaus(
    client: httpx.AsyncClient, urls: list[str], api_key: str | None
) -> tuple[IntelStatus, list[Finding]]:
    if not api_key:
        return IntelStatus(source="URLhaus (abuse.ch)", status="skipped", detail="No Auth-Key configured"), []
    if not urls:
        return IntelStatus(source="URLhaus (abuse.ch)", status="ok", detail="No links to check"), []
    batch = urls[:MAX_URLHAUS_URLS]
    results = await asyncio.gather(*(_urlhaus_one(client, u, api_key) for u in batch), return_exceptions=True)
    errors = sum(isinstance(r, Exception) for r in results)
    if errors == len(batch):
        return IntelStatus(source="URLhaus (abuse.ch)", status="error", detail="All lookups failed"), []

    findings: list[Finding] = []
    for url, result in zip(batch, results, strict=True):
        if isinstance(result, dict):
            threat = result.get("threat") or "malware distribution"
            status = result.get("url_status") or "unknown"
            findings.append(
                Finding(
                    rule="urlhaus_match",
                    category=Category.THREAT_INTEL,
                    severity=Severity.CRITICAL,
                    title="Link is a known malware URL",
                    detail=f"URLhaus lists this link for {threat.replace('_', ' ')} (status: {status}).",
                    evidence=url,
                )
            )
    detail = f"Checked {len(batch)} link(s), {len(findings)} flagged"
    if errors:
        detail += f", {errors} lookup(s) failed"
    return IntelStatus(source="URLhaus (abuse.ch)", status="ok", detail=detail), findings


async def run_intel(
    urls: list[str], settings: Settings, client: httpx.AsyncClient | None = None
) -> tuple[list[IntelStatus], list[Finding]]:
    targets = web_urls(urls)
    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=settings.intel_timeout_seconds)
    try:
        (sb_status, sb_findings), (uh_status, uh_findings) = await asyncio.gather(
            check_safe_browsing(client, targets, settings.safe_browsing_key),
            check_urlhaus(client, targets, settings.urlhaus_key),
        )
    finally:
        if owns_client:
            await client.aclose()
    return [sb_status, uh_status], sb_findings + uh_findings
