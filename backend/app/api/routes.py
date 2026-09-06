from fastapi import APIRouter, UploadFile, File, HTTPException

from app.services.email_parser import parse_email

router = APIRouter(prefix="/api", tags=["Email Analysis"])


@router.get("/health")
async def health():
    return {"status": "healthy"}


@router.post("/upload-email")
async def upload_email(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported."
        )

    contents = await file.read()
    return parse_email(contents)