"""Sender authentication (SPF/DKIM/DMARC) and sender-identity checks."""

from __future__ import annotations

import re

from phishlens.checks.domains import (
    FREE_MAIL_DOMAINS,
    brand_in_text,
    is_official_domain,
    lookalike_brand,
    registrable_domain,
)
from phishlens.models import AuthResults, Category, Finding, Severity
from phishlens.parser import ParsedEmail, domain_of_address

_RESULT_RE = {mech: re.compile(rf"(?i)\b{mech}\s*=\s*([a-z]+)") for mech in ("spf", "dkim", "dmarc")}


def parse_auth_results(parsed: ParsedEmail) -> AuthResults:
    """Read SPF/DKIM/DMARC verdicts recorded by the receiving mail server.

    The first Authentication-Results header is the one added by the recipient's
    own provider (e.g. Gmail), so it is the most trustworthy.
    """
    results = AuthResults()
    for header in parsed.auth_results[:1]:
        for mech, pattern in _RESULT_RE.items():
            match = pattern.search(header)
            if match:
                setattr(results, mech, match.group(1).lower())
    if results.spf is None and parsed.received_spf:
        match = re.match(r"\s*([a-z]+)", parsed.received_spf[0], re.I)
        if match:
            results.spf = match.group(1).lower()
    return results


def check_authentication(parsed: ParsedEmail, auth: AuthResults) -> list[Finding]:
    findings: list[Finding] = []
    if not parsed.has_headers:
        findings.append(
            Finding(
                rule="no_headers",
                category=Category.AUTHENTICATION,
                severity=Severity.INFO,
                title="Only the message body was provided",
                detail="Sender checks need the full original source. In Gmail, open the email, "
                "click ⋮ → Show original, and paste everything.",
            )
        )
        return findings

    if auth.spf is None and auth.dkim is None and auth.dmarc is None:
        findings.append(
            Finding(
                rule="no_auth_results",
                category=Category.AUTHENTICATION,
                severity=Severity.INFO,
                title="No authentication results in the headers",
                detail="The headers don't record SPF, DKIM, or DMARC checks, so the sender "
                "couldn't be verified. Forwarded emails often lose these headers.",
            )
        )
        return findings

    if auth.dmarc in ("fail",):
        findings.append(
            Finding(
                rule="dmarc_fail",
                category=Category.AUTHENTICATION,
                severity=Severity.HIGH,
                title="DMARC failed",
                detail="The sending server isn't authorized by the domain in the From address. "
                "This is a strong sign the sender is spoofed.",
                evidence=f"dmarc={auth.dmarc}",
            )
        )
    if auth.spf in ("fail",):
        findings.append(
            Finding(
                rule="spf_fail",
                category=Category.AUTHENTICATION,
                severity=Severity.MEDIUM,
                title="SPF failed",
                detail="The server that sent this email is not on the sender domain's list of allowed servers.",
                evidence=f"spf={auth.spf}",
            )
        )
    elif auth.spf in ("softfail", "permerror"):
        findings.append(
            Finding(
                rule="spf_softfail",
                category=Category.AUTHENTICATION,
                severity=Severity.LOW,
                title=f"SPF {auth.spf}",
                detail="The sending server isn't clearly authorized by the sender's domain.",
                evidence=f"spf={auth.spf}",
            )
        )
    if auth.dkim in ("fail", "permerror"):
        findings.append(
            Finding(
                rule="dkim_fail",
                category=Category.AUTHENTICATION,
                severity=Severity.MEDIUM,
                title="DKIM signature failed",
                detail="The email's cryptographic signature didn't verify, so it may have been "
                "forged or altered in transit.",
                evidence=f"dkim={auth.dkim}",
            )
        )
    if not findings and "pass" in (auth.spf, auth.dkim, auth.dmarc):
        findings.append(
            Finding(
                rule="auth_pass",
                category=Category.AUTHENTICATION,
                severity=Severity.INFO,
                title="Sender authentication passed",
                detail="The sending domain authorized this email. That proves who sent it, not "
                "that they're trustworthy: attackers can pass these checks on domains "
                "they register themselves.",
            )
        )
    return findings


def check_sender(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    from_domain = parsed.from_domain
    display = parsed.from_display or ""

    # Display name contains a different email address: "support@paypal.com <x@evil.ru>"
    embedded = re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", display)
    for addr in embedded:
        if addr.lower() != (parsed.from_address or ""):
            findings.append(
                Finding(
                    rule="display_name_address_mismatch",
                    category=Category.SENDER,
                    severity=Severity.HIGH,
                    title="Display name shows a different email address",
                    detail=f"The name shown in your inbox includes '{addr}', but the email "
                    f"actually came from '{parsed.from_address}'.",
                    evidence=f"From: {display} <{parsed.from_address}>",
                )
            )
            break

    # Brand named in the display name but sent from an unrelated domain.
    brand = brand_in_text(display)
    if brand and from_domain and not is_official_domain(from_domain, brand):
        free = registrable_domain(from_domain) in FREE_MAIL_DOMAINS
        findings.append(
            Finding(
                rule="brand_display_mismatch",
                category=Category.SENDER,
                severity=Severity.HIGH,
                title="Sender name doesn't match the sending domain",
                detail=f"The sender calls itself '{display}', but the email came from "
                f"{'a free webmail account' if free else 'the unrelated domain'} "
                f"'{from_domain}'.",
                evidence=f"From: {display} <{parsed.from_address}>",
            )
        )

    # Lookalike sender domain.
    look = lookalike_brand(from_domain)
    if look:
        findings.append(
            Finding(
                rule="lookalike_sender_domain",
                category=Category.SENDER,
                severity=Severity.HIGH,
                title="Sender domain imitates a known brand",
                detail=look[1] + ".",
                evidence=from_domain,
            )
        )

    if from_domain and any(label.startswith("xn--") for label in from_domain.split(".")):
        findings.append(
            Finding(
                rule="punycode_sender",
                category=Category.SENDER,
                severity=Severity.HIGH,
                title="Sender domain uses encoded international characters",
                detail="Punycode domains (xn--) can display as letters that look identical to a real brand's domain.",
                evidence=from_domain,
            )
        )

    # Replies go somewhere other than the sender.
    reply_domain = domain_of_address(parsed.reply_to)
    if reply_domain and from_domain and registrable_domain(reply_domain) != registrable_domain(from_domain):
        findings.append(
            Finding(
                rule="reply_to_mismatch",
                category=Category.SENDER,
                severity=Severity.MEDIUM,
                title="Replies go to a different domain",
                detail=f"If you hit reply, your message goes to '{parsed.reply_to}', not the "
                f"sender's domain '{from_domain}'.",
                evidence=f"Reply-To: {parsed.reply_to}",
            )
        )

    return_domain = domain_of_address(parsed.return_path)
    if return_domain and from_domain and registrable_domain(return_domain) != registrable_domain(from_domain):
        findings.append(
            Finding(
                rule="return_path_mismatch",
                category=Category.SENDER,
                severity=Severity.LOW,
                title="Bounce address uses a different domain",
                detail="The Return-Path domain differs from the From domain. Mailing services do "
                "this legitimately, so this only matters alongside other signs.",
                evidence=f"Return-Path: {parsed.return_path}",
            )
        )
    return findings
