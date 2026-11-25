"""Runs every check on an email and assembles the report."""

from __future__ import annotations

import httpx

from phishlens.checks.content import check_attachments, check_content
from phishlens.checks.headers import check_authentication, check_sender, parse_auth_results
from phishlens.checks.links import analyze_links
from phishlens.config import Settings, get_settings
from phishlens.explain import llm_explanation, template_explanation
from phishlens.intel import run_intel
from phishlens.models import EmailSummary, Report
from phishlens.parser import parse_email
from phishlens.scoring import score_findings, sort_findings


async def analyze(
    raw: str | bytes,
    settings: Settings | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> Report:
    settings = settings or get_settings()
    parsed = parse_email(raw)
    auth = parse_auth_results(parsed)

    summary = EmailSummary(
        subject=parsed.subject,
        from_display=parsed.from_display,
        from_address=parsed.from_address,
        from_domain=parsed.from_domain,
        reply_to=parsed.reply_to,
        return_path=parsed.return_path,
        date=parsed.date,
        auth=auth,
    )

    findings = []
    findings += check_authentication(parsed, auth)
    findings += check_sender(parsed)
    links, link_findings = analyze_links(parsed.links)
    findings += link_findings
    findings += check_content(parsed.subject, parsed.visible_text)
    attachments, attachment_findings = check_attachments(parsed.attachments)
    findings += attachment_findings

    intel_status, intel_findings = await run_intel([link.url for link in links], settings, http_client)
    findings += intel_findings

    findings = sort_findings(findings)
    score, verdict = score_findings(findings)

    explanation = await llm_explanation(settings, verdict, score, summary, findings)
    source = "llm" if explanation else "template"
    if not explanation:
        explanation = template_explanation(verdict, findings)

    return Report(
        score=score,
        verdict=verdict,
        explanation=explanation,
        explanation_source=source,
        email=summary,
        findings=findings,
        links=links,
        attachments=attachments,
        intel=intel_status,
    )
