"""FastAPI app: JSON API plus the single-page web UI."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from phishlens import __version__
from phishlens.analyzer import analyze
from phishlens.config import get_settings
from phishlens.models import Report

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
SAMPLES = {"phishing": BASE_DIR / "samples" / "phishing.eml", "legitimate": BASE_DIR / "samples" / "legitimate.eml"}

app = FastAPI(
    title="PhishLens",
    version=__version__,
    description="Analyze a suspicious email for phishing signs: sender authentication, "
    "spoofing, deceptive links, risky attachments, and threat-intel matches.",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class AnalyzeRequest(BaseModel):
    raw: str = Field(min_length=1, description="Full email source (headers + body) or just the body")


# --- Security middleware -----------------------------------------------------

_SECURITY_HEADERS = {
    # The UI renders attacker-controlled email content, so lock the page down hard.
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; "
    "script-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

_hits: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/analyze"):
        limit = get_settings().rate_limit_per_minute
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window = _hits[client]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit:
            return PlainTextResponse("Too many requests. Try again in a minute.", status_code=429)
        window.append(now)
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        # FastAPI's interactive /docs page loads its UI from a CDN, so it gets a looser policy.
        if name == "Content-Security-Policy" and request.url.path in ("/docs", "/redoc"):
            continue
        response.headers.setdefault(name, value)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def _check_size(size: int) -> None:
    limit = get_settings().max_email_bytes
    if size > limit:
        raise HTTPException(status_code=413, detail=f"Email is too large (limit {limit // 1000} KB).")


# --- Routes ------------------------------------------------------------------


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict:
    s = get_settings()
    return {
        "status": "ok",
        "version": __version__,
        "safe_browsing": bool(s.safe_browsing_key),
        "urlhaus": bool(s.urlhaus_key),
        "llm": bool(s.anthropic_key),
    }


@app.post("/api/analyze", response_model=Report)
async def analyze_text(body: AnalyzeRequest) -> Report:
    _check_size(len(body.raw.encode("utf-8", errors="ignore")))
    return await analyze(body.raw)


@app.post("/api/analyze/file", response_model=Report)
async def analyze_file(file: Annotated[UploadFile, File()]) -> Report:
    limit = get_settings().max_email_bytes
    data = await file.read(limit + 1)
    _check_size(len(data))
    if not data.strip():
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    return await analyze(data)


@app.get("/api/samples/{name}", response_class=PlainTextResponse)
async def sample(name: str) -> str:
    path = SAMPLES.get(name)
    if not path:
        raise HTTPException(status_code=404, detail="Unknown sample")
    return path.read_text(encoding="utf-8")
