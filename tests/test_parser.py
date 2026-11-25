from phishlens.parser import parse_email


def test_parses_headers_links_and_attachments(phishing_raw):
    parsed = parse_email(phishing_raw)
    assert parsed.has_headers
    assert parsed.subject.startswith("Urgent")
    assert parsed.from_display == "PayPal Security"
    assert parsed.from_address == "service@paypal.com"
    assert parsed.from_domain == "paypal.com"
    assert parsed.reply_to == "resolution-team@mailbox.example"
    assert len(parsed.auth_results) == 1

    urls = [link.url for link in parsed.links]
    assert "http://paypal.com.account-verify.example/signin?id=8832" in urls
    assert "http://192.0.2.44/secure/update" in urls
    deceptive = next(link for link in parsed.links if "account-verify" in link.url)
    assert deceptive.text == "https://www.paypal.com/signin"

    assert [a.filename for a in parsed.attachments] == ["Account_Statement.pdf.html"]


def test_accepts_bytes(phishing_raw):
    parsed = parse_email(phishing_raw.encode())
    assert parsed.from_address == "service@paypal.com"


def test_body_only_paste_is_treated_as_body():
    parsed = parse_email("Hi, please review this invoice: https://bit.ly/abc123 thanks")
    assert not parsed.has_headers
    assert parsed.links[0].url == "https://bit.ly/abc123"


def test_html_form_is_extracted():
    raw = (
        "From: a@b.com\nSubject: hi\nContent-Type: text/html\n\n"
        '<form action="https://collect.example/steal"><input name="pw"></form>'
    )
    parsed = parse_email(raw)
    assert any(link.source == "form" and "collect.example" in link.url for link in parsed.links)


def test_malformed_input_does_not_crash():
    parsed = parse_email("From: <<<>>>\nSubject:\n\n<a href=")
    assert parsed is not None
