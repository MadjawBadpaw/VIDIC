from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.schemas.email_schema import HealthResponse

app = FastAPI(
    title="VIDIC Backend",
    description=(
        "Online Email Threat Investigation API. Parses RFC5322 (.eml) emails "
        "and performs live threat intelligence enrichment using RDAP, IPWhois, "
        "VirusTotal and URLhaus."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/", tags=["Health"], response_model=HealthResponse)
def root():
    return HealthResponse(
        message="VIDIC Backend API is running.",
        version="1.0.0",
        status="healthy",
    )