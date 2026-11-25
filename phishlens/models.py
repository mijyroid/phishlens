"""Data models shared by the analyzer and the API."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Points each severity adds to the 0-100 risk score.
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 60,
}


class Category(StrEnum):
    AUTHENTICATION = "authentication"
    SENDER = "sender"
    LINKS = "links"
    CONTENT = "content"
    ATTACHMENTS = "attachments"
    THREAT_INTEL = "threat_intel"


class Verdict(StrEnum):
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    LIKELY_PHISHING = "likely_phishing"


class Finding(BaseModel):
    rule: str = Field(description="Stable identifier of the check that fired")
    category: Category
    severity: Severity
    title: str
    detail: str
    evidence: str | None = None


class LinkInfo(BaseModel):
    url: str
    text: str | None = None
    domain: str | None = None
    flags: list[str] = Field(default_factory=list)


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str
    size: int


class AuthResults(BaseModel):
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None


class EmailSummary(BaseModel):
    subject: str | None = None
    from_display: str | None = None
    from_address: str | None = None
    from_domain: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    date: str | None = None
    auth: AuthResults = Field(default_factory=AuthResults)


class IntelStatus(BaseModel):
    source: str
    status: str  # "ok", "skipped", or "error"
    detail: str | None = None


class Report(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    explanation: str
    explanation_source: str  # "template" or "llm"
    email: EmailSummary
    findings: list[Finding]
    links: list[LinkInfo]
    attachments: list[AttachmentInfo]
    intel: list[IntelStatus]
