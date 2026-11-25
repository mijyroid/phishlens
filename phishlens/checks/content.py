"""Message content and attachment checks."""

from __future__ import annotations

import re

from phishlens.models import AttachmentInfo, Category, Finding, Severity
from phishlens.parser import RawAttachment

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b",
    r"\bimmediate(ly)?\b",
    r"\bwithin \d+ (hours?|days?)\b",
    r"\b(account|access) (will be|has been) (suspended|closed|locked|disabled|terminated|limited)\b",
    r"\bfinal (notice|warning|reminder)\b",
    r"\bact now\b",
    r"\b(unusual|suspicious) (activity|sign[- ]?in|login)\b",
    r"\bverify your (account|identity|information)\b",
    r"\bconfirm your (account|identity|information|details)\b",
    r"\bfailure to (comply|respond|verify)\b",
    r"\bexpires? (today|soon|in \d+)\b",
]

SENSITIVE_PATTERNS = [
    r"\bpassword\b",
    r"\bsocial security\b",
    r"\bssn\b",
    r"\b(login|sign[- ]in) credentials\b",
    r"\bbank account (number|details|information)\b",
    r"\bcredit card (number|details|information)\b",
    r"\bgift cards?\b",
    r"\bwire transfer\b",
    r"\b(update|verify|confirm) (your )?(payment|billing) (method|information|details)\b",
    r"\b(one[- ]time|verification) (code|passcode)\b",
]

GENERIC_GREETINGS = [
    r"\bdear (valued )?(customer|user|client|member|account holder|sir/madam|sir or madam)\b",
    r"\bdear (e-?mail|account) (user|owner)\b",
]

EXECUTABLE_EXT = {
    "exe",
    "scr",
    "js",
    "jse",
    "vbs",
    "vbe",
    "bat",
    "cmd",
    "ps1",
    "jar",
    "msi",
    "com",
    "pif",
    "hta",
    "lnk",
    "iso",
    "img",
    "vhd",
    "wsf",
    "cpl",
    "reg",
    "apk",
    "dmg",
    "app",
}
HTML_EXT = {"html", "htm", "shtml", "svg", "xhtml"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab", "ace"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "png"}


def _matches(patterns: list[str], text: str) -> list[str]:
    hits: list[str] = []
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            hits.append(match.group(0))
    return hits


def check_content(subject: str | None, body: str) -> list[Finding]:
    findings: list[Finding] = []
    text = f"{subject or ''}\n{body}"

    urgency = _matches(URGENCY_PATTERNS, text)
    if urgency:
        findings.append(
            Finding(
                rule="urgency_language",
                category=Category.CONTENT,
                severity=Severity.MEDIUM if len(urgency) >= 2 else Severity.LOW,
                title="Pressure or urgency language",
                detail="Phishing emails rush you so you act before thinking. Phrases found: "
                + ", ".join(f"'{h}'" for h in urgency[:4])
                + ".",
                evidence="; ".join(urgency[:4]),
            )
        )

    sensitive = _matches(SENSITIVE_PATTERNS, text)
    if sensitive:
        findings.append(
            Finding(
                rule="sensitive_request",
                category=Category.CONTENT,
                severity=Severity.MEDIUM,
                title="Mentions passwords, payments, or personal data",
                detail="Legitimate companies rarely ask for these by email. Terms found: "
                + ", ".join(f"'{h}'" for h in sensitive[:4])
                + ".",
                evidence="; ".join(sensitive[:4]),
            )
        )

    greeting = _matches(GENERIC_GREETINGS, text)
    if greeting:
        findings.append(
            Finding(
                rule="generic_greeting",
                category=Category.CONTENT,
                severity=Severity.LOW,
                title="Generic greeting",
                detail=f"The email opens with '{greeting[0]}' instead of your name, which is common "
                "in mass phishing campaigns.",
                evidence=greeting[0],
            )
        )
    return findings


def check_attachments(attachments: list[RawAttachment]) -> tuple[list[AttachmentInfo], list[Finding]]:
    infos: list[AttachmentInfo] = []
    findings: list[Finding] = []
    for att in attachments:
        infos.append(AttachmentInfo(filename=att.filename, content_type=att.content_type, size=att.size))
        name = att.filename.lower().strip()
        parts = name.rsplit(".", 2)
        ext = parts[-1] if len(parts) > 1 else ""
        inner = parts[-2] if len(parts) > 2 else ""

        if ext in EXECUTABLE_EXT and inner in DOC_EXT:
            findings.append(
                Finding(
                    rule="double_extension",
                    category=Category.ATTACHMENTS,
                    severity=Severity.CRITICAL,
                    title="Attachment disguised with a double extension",
                    detail=f"'{att.filename}' looks like a .{inner} file but is actually a .{ext} "
                    "program that can run on your computer.",
                    evidence=att.filename,
                )
            )
        elif ext in EXECUTABLE_EXT:
            findings.append(
                Finding(
                    rule="executable_attachment",
                    category=Category.ATTACHMENTS,
                    severity=Severity.CRITICAL,
                    title="Executable attachment",
                    detail=f"'{att.filename}' can run code on your computer. Don't open it.",
                    evidence=att.filename,
                )
            )
        elif ext in HTML_EXT:
            findings.append(
                Finding(
                    rule="html_attachment",
                    category=Category.ATTACHMENTS,
                    severity=Severity.HIGH,
                    title="Web page sent as an attachment",
                    detail=f"'{att.filename}' opens in your browser. Attackers use these to show fake "
                    "login pages that steal passwords.",
                    evidence=att.filename,
                )
            )
        elif ext in MACRO_EXT:
            findings.append(
                Finding(
                    rule="macro_attachment",
                    category=Category.ATTACHMENTS,
                    severity=Severity.HIGH,
                    title="Office file with macros",
                    detail=f"'{att.filename}' can contain macros, a common way to install malware.",
                    evidence=att.filename,
                )
            )
        elif ext in ARCHIVE_EXT:
            findings.append(
                Finding(
                    rule="archive_attachment",
                    category=Category.ATTACHMENTS,
                    severity=Severity.MEDIUM,
                    title="Compressed archive attachment",
                    detail=f"'{att.filename}' is an archive, which is often used to slip malware past email filters.",
                    evidence=att.filename,
                )
            )
    return infos, findings
