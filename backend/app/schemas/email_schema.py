from typing import Optional

from pydantic import BaseModel, Field


# ==========================================================
# Metadata
# ==========================================================

class Metadata(BaseModel):
    email_sha256: str
    size_bytes: int
    parser_version: str


# ==========================================================
# Email Headers
# ==========================================================

class Headers(BaseModel):
    subject: Optional[str] = None
    from_: Optional[str] = Field(default=None, alias="from")
    to: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None

    # Parsed from `from_` so the frontend doesn't have to re-parse a raw
    # "Display Name <email@domain>" string itself.
    from_email: Optional[str] = None
    from_domain: Optional[str] = None
    display_name: Optional[str] = None

    model_config = {"populate_by_name": True}


class Authentication(BaseModel):
    return_path: Optional[str] = None
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    return_path_mismatch: Optional[bool] = None

    # Parsed from return_path for the same reason as headers.from_domain.
    return_path_domain: Optional[str] = None


# ==========================================================
# Attachments
# ==========================================================

class Attachment(BaseModel):
    filename: Optional[str] = None
    extension: Optional[str] = None
    mime_type: str
    size: int
    sha256: str


# ==========================================================
# IOC Extraction
# ==========================================================

class IOCCounts(BaseModel):
    urls: int
    domains: int
    emails: int
    ips: int


class IOCResult(BaseModel):
    urls: list[str]
    domains: list[str]
    emails: list[str]
    ips: list[str]
    counts: IOCCounts


# ==========================================================
# Risk Engine
# ==========================================================

class RiskResult(BaseModel):
    score: int
    verdict: str
    confidence: int
    reasons: list[str]


# ==========================================================
# Routing
# ==========================================================

class RoutingTimestamp(BaseModel):
    iso: str
    display: str


class RoutingHop(BaseModel):
    hop: int
    server: str
    ip: Optional[str] = None
    timestamp: RoutingTimestamp
    raw: str


class Routing(BaseModel):
    origin_ip: Optional[str] = None
    hop_count: int
    received_chain: list[RoutingHop]


# ==========================================================
# Domain Intelligence
# ==========================================================

class DomainInfo(BaseModel):
    domain: str
    registrar: Optional[str] = None
    created: Optional[str] = None
    age_days: Optional[int] = None

    # Keep if you're using recent-domain detection.
    is_recent_domain: bool = False

    tld: str
    status: str


# ==========================================================
# AbuseIPDB Intelligence
# ==========================================================

class AbuseIPDBInfo(BaseModel):
    status: str

    abuse_confidence_score: Optional[int] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    reports: Optional[int] = None
    last_reported: Optional[str] = None


# ==========================================================
# IP Intelligence
# ==========================================================

class IPInfo(BaseModel):
    ip: str

    asn: Optional[str] = None
    organization: Optional[str] = None
    network_country: Optional[str] = None
    cidr: Optional[str] = None
    network_name: Optional[str] = None

    hosting: Optional[bool] = None
    status: str

    abuseipdb: Optional[AbuseIPDBInfo] = None


class DomainIntelligence(BaseModel):
    online_lookup: bool

    # CHANGED: `lookup_provider` removed. It was a hardcoded string
    # ("RDAP + IPWhois + AbuseIPDB + VirusTotal + URLhaus") that never
    # reflected what actually ran for a given request — if, say,
    # AbuseIPDB's API key were missing and it silently returned
    # "unavailable", this field would still falsely claim it ran. Static
    # info like this belongs on /health, not on a per-request response.
    domains: list[DomainInfo]
    ips: list[IPInfo]


# ==========================================================
# Reputation Intelligence
# ==========================================================

class VirusTotalReputation(BaseModel):
    status: str
    malicious: Optional[int] = None
    suspicious: Optional[int] = None
    harmless: Optional[int] = None
    undetected: Optional[int] = None
    timeout: Optional[int] = None
    reputation: Optional[int] = None


class URLHausReputation(BaseModel):
    status: str
    threat: Optional[str] = None
    url_status: Optional[str] = None
    tags: list[str] = []
    reporter: Optional[str] = None


class URLReputation(BaseModel):
    virustotal: VirusTotalReputation
    urlhaus: URLHausReputation


# ==========================================================
# Final API Response
# ==========================================================

class EmailAnalysisResponse(BaseModel):
    metadata: Metadata
    headers: Headers
    authentication: Authentication

    body_preview: str
    body_length: int

    attachments: list[Attachment]

    iocs: IOCResult

    risk: RiskResult

    routing: Routing

    domain_intelligence: DomainIntelligence

    reputation: dict[str, URLReputation]


# ==========================================================
# Health Endpoint
# ==========================================================

class HealthResponse(BaseModel):
    message: str
    version: str
    status: str

    # NEW: static description of which intel providers this build wires
    # up. Lives here instead of on every analysis response.
    intel_providers: list[str] = [
        "RDAP",
        "IPWhois",
        "VirusTotal",
        "URLhaus",
        "AbuseIPDB",
    ]