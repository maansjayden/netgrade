import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from netgrade.models import ScanResult, CheckResult
from netgrade.audio import ElevenLabsAudioGenerator
from netgrade.api import router as api_router
from netgrade.context import DomainNotFoundError
from netgrade.domains import InvalidDomainError
from netgrade.middleware import RateLimitMiddleware
from netgrade.service import ScanService

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Open one engine for the process, and close it on shutdown.

    The connection pool, DNS resolver, outbound concurrency bound and result
    cache are all per-process rather than per-request. Building them per
    request would mean a new pool on every scan and a cache that never hits.
    """
    async with ScanService.open() as service:
        app.state.service = service
        logger.info("scan engine ready")
        yield
    logger.info("scan engine closed")


# Initialize FastAPI Application Scaffolding & Routing
app = FastAPI(
    title="Netgrade Security Posture Scanner",
    description="Passive security posture scanner designed for small businesses",
    version="1.0.0",
    lifespan=lifespan
)

# Applies to the HTML pages as well as the JSON API: both are front doors onto
# the same expensive work, so limiting only one of them would not be a limit.
app.add_middleware(RateLimitMiddleware)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
static_dir = os.path.join(BASE_DIR, "static")
templates_dir = os.path.join(BASE_DIR, "templates")

if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

templates = Jinja2Templates(directory=templates_dir if os.path.exists(templates_dir) else BASE_DIR)
audio_gen = ElevenLabsAudioGenerator()


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail}
        )
    
    if exc.status_code == 404:
        if exc.detail == "Not Found":
            title = "Page Not Found (404)"
            message = "The requested page or route does not exist. Check the URL or try scanning a domain."
        else:
            title = "Domain Doesn't Exist"
            message = exc.detail
    elif exc.status_code == 400:
        title = "Invalid Domain Name"
        message = exc.detail if exc.detail else "Please enter a valid domain name (e.g. example.com)."
    elif exc.status_code == 503:
        title = "Service Unavailable"
        message = exc.detail if exc.detail else "The scanner service is currently unavailable. Please try again later."
    else:
        title = f"Error {exc.status_code}"
        message = str(exc.detail)

    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={
            "title": title,
            "message": message,
            "status_code": exc.status_code
        },
        status_code=exc.status_code
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s: %s", request.url.path, exc, exc_info=True)
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error."}
        )
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={
            "title": "Internal Server Error (500)",
            "message": "An unexpected error occurred while executing the scan. Please try again in a few moments.",
            "status_code": 500
        },
        status_code=500
    )


# JSON contract routes under /api/v1. Schema is published at /docs.
app.include_router(api_router)


def load_mock_scan(domain: str) -> ScanResult:
    """Load the sample report fixture.

    This is illustrative data, not a scan. It may only be served from routes
    whose name makes that obvious to the user (``/sample-report``). It must
    never be substituted for a real scan result on an error path.
    """
    fixture_path = os.path.join(BASE_DIR, "tests", "fixtures", "mock_scan.json")
    if os.path.exists(fixture_path):
        with open(fixture_path, "r") as f:
            data = json.load(f)
            data["domain"] = domain
            data["scanned_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            return ScanResult(**data)
    
    # Fallback inline mock
    return ScanResult(
        domain=domain,
        scanned_at=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        grade="C",
        score=61,
        checks=[
            CheckResult(
                id="email_spoofing",
                title="Email spoofing protection",
                status="fail",
                severity="high",
                summary="No DMARC policy is published.",
                explanation="Anyone can send email that appears to come from your domain.",
                fix="Publish a DMARC record starting at p=none, then tighten to p=reject.",
                evidence={"dmarc_record": None, "spf_record": "v=spf1 include:_spf.google.com ~all"}
            ),
            CheckResult(
                id="tls_config",
                title="TLS/SSL configuration",
                status="pass",
                severity="low",
                summary="Valid TLS 1.3 certificate detected.",
                explanation="Your site enforces modern encrypted HTTPS connections.",
                fix="Maintain certificate auto-renewal.",
                evidence={"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "days_remaining": 64}
            )
        ]
    )


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "netgrade"}


def _service(request: Request) -> ScanService:
    service = getattr(request.app.state, "service", None)
    if not isinstance(service, ScanService):
        raise HTTPException(
            status_code=503,
            detail="Scan engine is not running.",
        )
    return service


@app.get("/", response_class=HTMLResponse)
async def home_page(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/scan", response_class=HTMLResponse)
async def scan_domain(request: Request, domain: str = "example.com", force: bool = False):
    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    
    try:
        service = _service(request)
        report = await service.scan(clean_domain, force=force)
    except InvalidDomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DomainNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    audio_url = await audio_gen.get_or_generate_audio(
        report.domain, report.grade, report.score, report.checks
    )
    report.audio_briefing_url = audio_url

    return templates.TemplateResponse(request, "report.html", {"report": report})


@app.get("/compare", response_class=HTMLResponse)
async def compare_domains(request: Request, domain1: str = None, domain2: str = None):
    report1 = None
    report2 = None
    if domain1 and domain2:
        # Both scanned concurrently against one shared connection pool. Until
        # now this route invented the second domain's posture -- a hardcoded
        # score of 84 -- and rendered it as a scan result, which is the same
        # class of problem as the sample-data fallback removed from /scan.
        try:
            service = _service(request)
            report1, report2 = await service.compare(domain1, domain2)
        except InvalidDomainError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except DomainNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return templates.TemplateResponse(request, "compare.html", {
        "domain1": domain1,
        "domain2": domain2,
        "report1": report1,
        "report2": report2
    })


@app.get("/sample-report", response_class=HTMLResponse)
async def sample_report(request: Request):
    report = load_mock_scan("sample-business.nl")
    audio_url = await audio_gen.get_or_generate_audio(
        report.domain, report.grade, report.score, report.checks
    )
    report.audio_briefing_url = audio_url
    return templates.TemplateResponse(request, "report.html", {"report": report})
