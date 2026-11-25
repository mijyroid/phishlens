import pytest

from phishlens.checks.content import check_attachments, check_content
from phishlens.checks.domains import lookalike_brand, registrable_domain
from phishlens.checks.headers import check_authentication, check_sender, parse_auth_results
from phishlens.checks.links import analyze_links
from phishlens.models import Severity
from phishlens.parser import RawAttachment, RawLink, parse_email


def rules(findings):
    return {f.rule for f in findings}


# --- domains -----------------------------------------------------------------


@pytest.mark.parametrize(
    "host, expected",
    [
        ("login.secure.paypal.com", "paypal.com"),
        ("shop.amazon.co.uk", "amazon.co.uk"),
        ("paypal.com", "paypal.com"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize(
    "host",
    [
        "paypa1.com",  # homoglyph
        "arnazon.com",  # rn -> m
        "paypal-secure-login.com",  # brand + words
        "paypal.com.account-verify.example",  # brand as subdomain
        "micros0ft.com",
    ],
)
def test_lookalikes_are_flagged(host):
    assert lookalike_brand(host) is not None


@pytest.mark.parametrize(
    "host",
    [
        "paypal.com",
        "www.paypal.com",
        "groups.google.com",
        "career.utdallas.edu",
        "github.com",
        "wikipedia.org",
        "upsidedown.com",
        "metallica.com",
    ],
)
def test_real_and_unrelated_domains_are_not_flagged(host):
    assert lookalike_brand(host) is None


# --- authentication and sender -------------------------------------------------


def test_failed_auth_is_reported(phishing_raw):
    parsed = parse_email(phishing_raw)
    auth = parse_auth_results(parsed)
    assert (auth.spf, auth.dkim, auth.dmarc) == ("fail", "none", "fail")
    found = rules(check_authentication(parsed, auth))
    assert {"dmarc_fail", "spf_fail"} <= found


def test_passing_auth_is_info_only(legit_raw):
    parsed = parse_email(legit_raw)
    findings = check_authentication(parsed, parse_auth_results(parsed))
    assert rules(findings) == {"auth_pass"}
    assert all(f.severity == Severity.INFO for f in findings)


def test_brand_in_display_name_from_webmail():
    parsed = parse_email('From: "Chase Fraud Alert" <chase.alerts2026@gmail.com>\nSubject: x\n\nhi')
    assert "brand_display_mismatch" in rules(check_sender(parsed))


def test_display_name_with_other_address():
    parsed = parse_email('From: "support@apple.com" <x@evil.example>\nSubject: x\n\nhi')
    assert "display_name_address_mismatch" in rules(check_sender(parsed))


def test_reply_to_mismatch(phishing_raw):
    assert "reply_to_mismatch" in rules(check_sender(parse_email(phishing_raw)))


def test_legit_sender_is_clean(legit_raw):
    assert check_sender(parse_email(legit_raw)) == []


# --- links -----------------------------------------------------------------------


def test_deceptive_link_text():
    _, findings = analyze_links([RawLink(url="https://evil.example/login", text="www.chase.com")])
    assert "link_text_mismatch" in rules(findings)


def test_file_name_in_link_text_is_not_a_mismatch():
    _, findings = analyze_links([RawLink(url="https://docs.github.com/x", text="Download report.pdf")])
    assert "link_text_mismatch" not in rules(findings)


@pytest.mark.parametrize(
    "url, rule",
    [
        ("http://203.0.113.5/login", "link_ip_host"),
        ("https://www.paypal.com@evil.example/login", "link_userinfo_trick"),
        ("https://bit.ly/3abc", "link_shortener"),
        ("https://xn--pypal-4ve.com/", "link_punycode"),
        ("javascript:alert(1)", "link_dangerous_scheme"),
        ("https://a.b.c.d.evil.example/", "link_many_subdomains"),
    ],
)
def test_risky_links(url, rule):
    _, findings = analyze_links([RawLink(url=url)])
    assert rule in rules(findings)


def test_low_severity_link_flags_are_reported_once():
    links = [RawLink(url=f"http://site{i}.example/") for i in range(5)]
    _, findings = analyze_links(links)
    assert [f.rule for f in findings].count("link_http") == 1


def test_mailto_links_are_ignored():
    infos, findings = analyze_links([RawLink(url="mailto:help@utdallas.edu")])
    assert findings == [] and infos[0].flags == []


# --- content and attachments ---------------------------------------------------


def test_urgency_and_sensitive_language():
    found = rules(check_content("Final notice", "Dear customer, verify your account immediately or send gift cards."))
    assert {"urgency_language", "sensitive_request", "generic_greeting"} <= found


def test_plain_message_has_no_content_findings():
    assert check_content("Lunch?", "Want to grab lunch after class on Friday?") == []


@pytest.mark.parametrize(
    "filename, rule, severity",
    [
        ("invoice.pdf.exe", "double_extension", Severity.CRITICAL),
        ("setup.exe", "executable_attachment", Severity.CRITICAL),
        ("login.html", "html_attachment", Severity.HIGH),
        ("budget.xlsm", "macro_attachment", Severity.HIGH),
        ("files.zip", "archive_attachment", Severity.MEDIUM),
    ],
)
def test_risky_attachments(filename, rule, severity):
    _, findings = check_attachments([RawAttachment(filename=filename, content_type="x", size=1)])
    assert findings[0].rule == rule and findings[0].severity == severity


def test_safe_attachment():
    _, findings = check_attachments([RawAttachment(filename="syllabus.pdf", content_type="application/pdf", size=1)])
    assert findings == []
