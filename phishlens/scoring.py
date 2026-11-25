"""Combine findings into a 0-100 risk score and a verdict."""

from __future__ import annotations

from phishlens.models import SEVERITY_WEIGHTS, Finding, Severity, Verdict

SUSPICIOUS_THRESHOLD = 25
PHISHING_THRESHOLD = 60

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def score_findings(findings: list[Finding]) -> tuple[int, Verdict]:
    score = min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings))
    if score >= PHISHING_THRESHOLD:
        verdict = Verdict.LIKELY_PHISHING
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.LOW_RISK
    return score, verdict


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _ORDER.index(f.severity))
