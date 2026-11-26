import pytest
from fastapi.testclient import TestClient

from phishlens import main


@pytest.fixture
def client():
    main._hits.clear()
    return TestClient(main.app)


def test_health(client):
    data = client.get("/api/health").json()
    assert data["status"] == "ok"
    assert data["safe_browsing"] is False


def test_index_has_security_headers(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "script-src 'self'" in res.headers["content-security-policy"]
    assert res.headers["x-frame-options"] == "DENY"


def test_index_includes_email_source_guide(client):
    html = client.get("/").text
    assert "How do I get an email's source?" in html
    for app in ("gmail", "outlook", "apple", "yahoo"):
        assert f'id="guide-{app}"' in html


def test_analyze_text(client, phishing_raw):
    res = client.post("/api/analyze", json={"raw": phishing_raw})
    assert res.status_code == 200
    body = res.json()
    assert body["verdict"] == "likely_phishing"
    assert res.headers["cache-control"] == "no-store"


def test_analyze_file(client, legit_raw):
    res = client.post("/api/analyze/file", files={"file": ("mail.eml", legit_raw.encode(), "message/rfc822")})
    assert res.status_code == 200
    assert res.json()["verdict"] == "low_risk"


def test_empty_input_rejected(client):
    assert client.post("/api/analyze", json={"raw": ""}).status_code == 422
    assert client.post("/api/analyze/file", files={"file": ("e.eml", b"  ", "text/plain")}).status_code == 400


def test_oversized_email_rejected(client, monkeypatch):
    monkeypatch.setenv("PHISHLENS_MAX_EMAIL_BYTES", "100")
    assert client.post("/api/analyze", json={"raw": "x" * 500}).status_code == 413
    res = client.post("/api/analyze/file", files={"file": ("e.eml", b"x" * 500, "text/plain")})
    assert res.status_code == 413


def test_rate_limit(client, monkeypatch):
    monkeypatch.setenv("PHISHLENS_RATE_LIMIT", "2")
    codes = [client.post("/api/analyze", json={"raw": "hello"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_samples(client):
    assert "PayPal" in client.get("/api/samples/phishing").text
    assert client.get("/api/samples/../../etc/passwd").status_code == 404
    assert client.get("/api/samples/nope").status_code == 404
