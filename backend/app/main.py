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

# Wildcard origins ("*") combined with allow_credentials=True is invalid per
# the CORS spec and most browsers will reject it outright. Pin this to the
# actual dev/prod frontend origin(s) instead. Update this list (or move it
# to an env var) when you deploy.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
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