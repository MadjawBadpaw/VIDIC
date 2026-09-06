from fastapi import APIRouter, File, HTTPException, UploadFile

from app.schemas.email_schema import EmailAnalysisResponse
from app.services.email_parser import parse_email

router = APIRouter()


@router.post(
    "/api/upload-email",
    response_model=EmailAnalysisResponse,
    tags=["Email Forensics"],
    summary="Upload Email",
    description=(
        "Upload an RFC5322 (.eml) email and perform an online phishing "
        "investigation with live threat intelligence enrichment using "
        "RDAP, IPWhois, VirusTotal and URLhaus."
    ),
)
async def upload_email(file: UploadFile = File(...)):
    """
    Accepts an RFC5322 .eml email file and returns a complete forensic analysis.
    """

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only RFC5322 .eml files are supported.",
        )

    try:
        email_bytes = await file.read()
        return parse_email(email_bytes)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Email parsing failed: {str(exc)}",
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
    }