"""Turn a raw email (pasted source or .eml bytes) into a structured object."""

from __future__ import annotations

import contextlib
import email
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'\)\]]+""")


@dataclass
class RawLink:
    url: str
    text: str | None = None
    source: str = "html"  # "html", "text", or "form"


@dataclass
class RawAttachment:
    filename: str
    content_type: str
    size: int


@dataclass
class ParsedEmail:
    subject: str | None = None
    from_display: str | None = None
    from_address: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    date: str | None = None
    auth_results: list[str] = field(default_factory=list)
    received_spf: list[str] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    links: list[RawLink] = field(default_factory=list)
    attachments: list[RawAttachment] = field(default_factory=list)
    has_headers: bool = False

    @property
    def from_domain(self) -> str | None:
        return domain_of_address(self.from_address)

    @property
    def visible_text(self) -> str:
        """Body text for content checks (plain text, or HTML with tags stripped)."""
        if self.text_body.strip():
            return self.text_body
        return _strip_html(self.html_body)


def domain_of_address(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().strip(">").lower() or None


class _LinkExtractor(HTMLParser):
    """Collects <a href> targets with their visible text, plus <form action> targets."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[RawLink] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "a" and attr.get("href"):
            self._href = attr["href"].strip()
            self._text = []
        elif tag == "form":
            action = (attr.get("action") or "").strip()
            self.links.append(RawLink(url=action or "(no action)", text=None, source="form"))

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split()) or None
            self.links.append(RawLink(url=self._href, text=text, source="html"))
            self._href = None
            self._text = []


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def _strip_html(html: str) -> str:
    extractor = _TextExtractor()
    try:
        extractor.feed(html)
    except Exception:  # malformed HTML should never break analysis
        return html
    return " ".join(" ".join(extractor.parts).split())


def _safe_content(part: EmailMessage) -> str:
    try:
        content = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        content = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)
    return content if isinstance(content, str) else ""


def _header(msg: EmailMessage, name: str) -> str | None:
    try:
        value = msg.get(name)
    except Exception:
        return None
    return str(value).strip() if value is not None else None


def _all_headers(msg: EmailMessage, name: str) -> list[str]:
    try:
        return [str(v) for v in (msg.get_all(name) or [])]
    except Exception:
        return []


def parse_email(raw: str | bytes) -> ParsedEmail:
    """Parse raw email source. Accepts full RFC 822 source or just a pasted body."""
    if isinstance(raw, bytes):
        msg = email.message_from_bytes(raw, policy=policy.default)
    else:
        msg = email.message_from_string(raw.lstrip(), policy=policy.default)

    parsed = ParsedEmail()
    parsed.has_headers = bool(msg.keys()) and any(
        h.lower() in ("from", "subject", "received", "to") for h in msg.keys()
    )

    if parsed.has_headers:
        parsed.subject = _header(msg, "Subject")
        from_raw = _header(msg, "From")
        if from_raw:
            name, addr = parseaddr(from_raw)
            parsed.from_display = name or None
            parsed.from_address = addr.lower() or None
        reply_to = _header(msg, "Reply-To")
        if reply_to:
            addrs = [a for _, a in getaddresses([reply_to]) if a]
            parsed.reply_to = addrs[0].lower() if addrs else None
        return_path = _header(msg, "Return-Path")
        if return_path:
            parsed.return_path = parseaddr(return_path)[1].lower() or None
        parsed.date = _header(msg, "Date")
        parsed.auth_results = _all_headers(msg, "Authentication-Results")
        parsed.received_spf = _all_headers(msg, "Received-SPF")

        for part in msg.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            disposition = (part.get_content_disposition() or "").lower()
            if filename or disposition == "attachment":
                payload = part.get_payload(decode=True) or b""
                parsed.attachments.append(
                    RawAttachment(
                        filename=filename or "(unnamed)",
                        content_type=part.get_content_type(),
                        size=len(payload),
                    )
                )
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain":
                parsed.text_body += _safe_content(part) + "\n"
            elif ctype == "text/html":
                parsed.html_body += _safe_content(part) + "\n"
    else:
        # No headers: treat the whole paste as the body.
        body = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
        if re.search(r"(?i)<(html|body|a|div|p|table)\b", body):
            parsed.html_body = body
        else:
            parsed.text_body = body

    parsed.links = _extract_links(parsed.html_body, parsed.text_body)
    return parsed


def _extract_links(html: str, text: str) -> list[RawLink]:
    links: list[RawLink] = []
    if html.strip():
        extractor = _LinkExtractor()
        with contextlib.suppress(Exception):  # keep whatever parsed before malformed HTML
            extractor.feed(html)
        links.extend(extractor.links)
    seen = {link.url for link in links}
    for match in URL_RE.findall(text):
        url = match.rstrip(".,;:!?")
        if url not in seen:
            links.append(RawLink(url=url, text=None, source="text"))
            seen.add(url)
    return links
