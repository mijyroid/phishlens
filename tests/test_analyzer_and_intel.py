import asyncio
import dataclasses
import json
from urllib.parse import parse_qs

import httpx

from phishlens.analyzer import analyze
from phishlens.intel import run_intel, web_urls
from phishlens.models import Verdict


def run(coro):
    return asyncio.run(coro)


def test_phishing_sample_is_flagged(phishing_raw, no_keys):
    report = run(analyze(phishing_raw, no_keys))
    assert report.verdict == Verdict.LIKELY_PHISHING
    assert report.score >= 60
    assert report.explanation_source == "template"
    assert report.findings[0].severity.value in ("critical", "high")  # sorted by severity


def test_legit_sample_is_low_risk(legit_raw, no_keys):
    report = run(analyze(legit_raw, no_keys))
    assert report.verdict == Verdict.LOW_RISK
    assert report.score == 0


def test_intel_skipped_without_keys(no_keys):
    statuses, findings = run(run_intel(["https://example.com"], no_keys))
    assert [s.status for s in statuses] == ["skipped", "skipped"]
    assert findings == []


def test_web_urls_filters_and_normalizes():
    assert web_urls(["mailto:a@b.com", "www.x.com", "https://y.com", "https://y.com"]) == [
        "http://www.x.com",
        "https://y.com",
    ]


def test_intel_matches_become_critical_findings(no_keys):
    keys = dataclasses.replace(no_keys, safe_browsing_key="sb-key", urlhaus_key="uh-key")
    bad = "http://malware.example/payload"

    def handler(request: httpx.Request) -> httpx.Response:
        if "safebrowsing" in request.url.host:
            body = json.loads(request.content)
            assert request.url.params["key"] == "sb-key"
            urls = [e["url"] for e in body["threatInfo"]["threatEntries"]]
            matches = [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": u}} for u in urls if u == bad]
            return httpx.Response(200, json={"matches": matches} if matches else {})
        assert request.headers["Auth-Key"] == "uh-key"
        if parse_qs(request.content.decode())["url"] == [bad]:
            hit = {"query_status": "ok", "threat": "malware_download", "url_status": "online"}
            return httpx.Response(200, json=hit)
        return httpx.Response(200, json={"query_status": "no_results"})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_intel([bad, "https://fine.example/"], keys, client)

    statuses, findings = run(go())
    assert [s.status for s in statuses] == ["ok", "ok"]
    assert {f.rule for f in findings} == {"safe_browsing_match", "urlhaus_match"}
    assert all(f.severity.value == "critical" for f in findings)
    assert "Advisory provided by Google" in next(f for f in findings if f.rule == "safe_browsing_match").detail


def test_intel_errors_are_reported_not_raised(no_keys):
    keys = dataclasses.replace(no_keys, safe_browsing_key="k", urlhaus_key="k")

    async def go():
        transport = httpx.MockTransport(lambda r: httpx.Response(500))
        async with httpx.AsyncClient(transport=transport) as client:
            return await run_intel(["https://x.example/"], keys, client)

    statuses, findings = run(go())
    assert [s.status for s in statuses] == ["error", "error"]
    assert findings == []
