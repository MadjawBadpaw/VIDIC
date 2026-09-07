import logging

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.schemas.email_schema import EmailAnalysisResponse
from app.services.email_parser import parse_email

router = APIRouter()

logger = logging.getLogger(__name__)

MAX_EMAIL_SIZE = 10 * 1024 * 1024  # 10 MB


@router.post(
    "/api/upload-email",
    response_model=EmailAnalysisResponse,
    tags=["Email Forensics"],
    summary="Upload Email",
    description=(
        "Upload an RFC5322 (.eml) email and perform an online phishing "
        "investigation with live threat intelligence enrichment using "
        "RDAP, IPWhois, VirusTotal, URLhaus and AbuseIPDB."
    ),
)
def upload_email(file: UploadFile = File(...)):
    """
    Accepts an RFC5322 .eml email file and returns a complete forensic analysis.

    CHANGED: this is now a plain `def`, not `async def`. FastAPI runs sync
    `def` routes in a threadpool automatically. parse_email() makes five
    sequential blocking network calls (RDAP, IPWhois, VirusTotal, URLhaus,
    AbuseIPDB) — VirusTotal alone can block ~10s while polling for
    analysis results. Under the old `async def`, all of that ran on the
    single event loop and would stall every other request (including
    /health) for the full duration of one upload.
    """

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only RFC5322 .eml files are supported.",
        )

    # Read with a hard cap so one oversized upload can't exhaust memory.
    # Reading one byte past the limit lets us detect "too large" without
    # first loading the entire file into memory.
    email_bytes = file.file.read(MAX_EMAIL_SIZE + 1)

    if len(email_bytes) > MAX_EMAIL_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Email exceeds the {MAX_EMAIL_SIZE // (1024 * 1024)} MB limit.",
        )

    try:
        return parse_email(email_bytes)

    except Exception:
        # Log the real exception server-side only. The client never sees
        # internal paths, library errors, or stack details.
        logger.exception("Email parsing failed for file: %s", file.filename)
        raise HTTPException(
            status_code=500,
            detail="Failed to analyze email. Please verify the file is a valid .eml message.",
        )


@router.get(
    "/health",
    tags=["Health"],
    summary="API Health Check",
)
def health():
    return {
        "message": "VIDIC Backend API is running.",
        "version": "1.0.0",
        "status": "healthy",
        "intel_providers": ["RDAP", "IPWhois", "VirusTotal", "URLhaus", "AbuseIPDB"],
    }