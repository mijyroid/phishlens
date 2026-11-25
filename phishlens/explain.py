"""Plain-English explanation of a report.

A template explanation always works. If ANTHROPIC_API_KEY is set, an LLM writes
a friendlier one. For privacy, the LLM only sees the findings, subject and
sender, never the email body.
"""

from __future__ import annotations

import json
import logging

from phishlens.config import Settings
from phishlens.models import EmailSummary, Finding, Severity, Verdict

log = logging.getLogger(__name__)

_VERDICT_LEAD = {
    Verdict.LIKELY_PHISHING: "This email is very likely a phishing attempt.",
    Verdict.SUSPICIOUS: "This email shows several warning signs. Treat it with caution.",
    Verdict.LOW_RISK: "No major warning signs were found in this email.",
}

_ADVICE = {
    Verdict.LIKELY_PHISHING: "Don't click its links, open attachments, or reply. If it claims to be "
    "from a company you use, go to their website or app directly, and "
    "report the email as phishing.",
    Verdict.SUSPICIOUS: "Before acting on it, verify the request through a channel you trust, "
    "like the company's official website or a phone number you already have.",
    Verdict.LOW_RISK: "Stay alert anyway: automated checks can't catch everything, especially "
    "requests from accounts that have been hacked.",
}


def _lower_first(title: str) -> str:
    """Lowercase the first word unless it's an acronym like DMARC or SPF."""
    first, _, rest = title.partition(" ")
    if first.isupper():
        return title
    return first.lower() + (" " + rest if rest else "")


def template_explanation(verdict: Verdict, findings: list[Finding]) -> str:
    serious = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    parts = [_VERDICT_LEAD[verdict]]
    if serious:
        reasons = "; ".join(_lower_first(f.title) for f in serious[:3])
        parts.append(f"The main reasons: {reasons}.")
    parts.append(_ADVICE[verdict])
    return " ".join(parts)


_SYSTEM_PROMPT = (
    "You explain phishing-analysis results to non-technical readers. Using only the findings "
    "provided, write 3-4 short sentences: the verdict, the two or three most important reasons "
    "in plain language, and what the reader should do next. Don't invent facts beyond the "
    "findings, don't use markdown, and don't tell the reader to click anything in the email."
)


async def llm_explanation(
    settings: Settings,
    verdict: Verdict,
    score: int,
    summary: EmailSummary,
    findings: list[Finding],
) -> str | None:
    if not settings.anthropic_key:
        return None
    try:
        from anthropic import AsyncAnthropic
    except ImportError:
        return None

    payload = {
        "verdict": verdict.value,
        "risk_score": score,
        "subject": summary.subject,
        "from": f"{summary.from_display or ''} <{summary.from_address or ''}>",
        "findings": [
            {"severity": f.severity.value, "title": f.title, "detail": f.detail}
            for f in findings
            if f.severity != Severity.INFO
        ][:12],
    }
    try:
        client = AsyncAnthropic(api_key=settings.anthropic_key, timeout=15)
        message = await client.messages.create(
            model=settings.llm_model,
            max_tokens=300,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(payload)}],
        )
        text = "".join(block.text for block in message.content if getattr(block, "type", "") == "text")
        return text.strip() or None
    except Exception as exc:  # any LLM failure falls back to the template
        log.warning("LLM explanation failed: %s", type(exc).__name__)
        return None
