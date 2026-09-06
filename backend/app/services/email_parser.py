import hashlib
from email import policy
from email.parser import BytesParser

from app.detectors.risk_engine import calculate_risk
from app.intel.reputation import build_reputation
from app.parsers.received_parser import parse_received_headers
from app.services.intel_service import enrich_analysis
from app.utils.ioc_extractor import extract_iocs

PARSER_VERSION = "1.0.0"


# ==========================================================
# Body Extraction
# ==========================================================

def extract_body(msg):
    """Extract plain text body from an RFC5322 email."""

    if msg.is_multipart():
        body_parts = []

        for part in msg.walk():
            if (
                part.get_content_type() == "text/plain"
                and part.get_content_disposition() != "attachment"
            ):
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_parts.append(payload.decode(errors="ignore"))

        return "\n".join(body_parts).strip()

    try:
        return msg.get_content().strip()
    except Exception:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode(errors="ignore").strip()

    return ""


# ==========================================================
# Authentication Extraction (FIXED SPF)
# ==========================================================

def extract_authentication(msg):
    auth_results = (msg.get("Authentication-Results") or "").lower()

    # ---------------- SPF ----------------

    spf = None
    received_spf = msg.get("Received-SPF")

    if received_spf:
        received_spf = received_spf.strip().lower()

        for status in (
            "pass",
            "fail",
            "softfail",
            "neutral",
            "temperror",
            "permerror",
        ):
            if received_spf.startswith(status):
                spf = status
                break

    # SPF fallback from Authentication-Results
    if spf is None:
        for status in (
            "pass",
            "fail",
            "softfail",
            "neutral",
            "temperror",
            "permerror",
        ):
            if f"spf={status}" in auth_results:
                spf = status
                break

    # ---------------- DKIM ----------------

    dkim = None

    if "dkim=pass" in auth_results:
        dkim = "pass"
    elif "dkim=fail" in auth_results:
        dkim = "fail"
    elif msg.get("DKIM-Signature"):
        dkim = "fail"

    # ---------------- DMARC ----------------

    dmarc = None

    if "dmarc=pass" in auth_results:
        dmarc = "pass"
    elif "dmarc=fail" in auth_results:
        dmarc = "fail"

    return {
        "return_path": msg.get("Return-Path"),
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
    }


# ==========================================================
# Attachment Extraction
# ==========================================================

def extract_attachments(msg):
    attachments = []

    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""

        filename = part.get_filename()

        extension = None
        if filename and "." in filename:
            extension = filename.rsplit(".", 1)[-1].lower()

        attachments.append(
            {
                "filename": filename,
                "extension": extension,
                "mime_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )

    return attachments


# ==========================================================
# Main Parser
# ==========================================================

def parse_email(email_bytes: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)

    body = extract_body(msg)
    attachments = extract_attachments(msg)

    headers = {
        "subject": msg.get("Subject"),
        "from": msg.get("From"),
        "to": msg.get("To"),
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID"),
    }

    authentication = extract_authentication(msg)

    # Routing parser returns a LIST of hops.
    received_chain = parse_received_headers(msg)

    routing = {
        "origin_ip": received_chain[0]["ip"] if received_chain else None,
        "hop_count": len(received_chain),
        "received_chain": received_chain,
    }

    # IOC extraction
    iocs = extract_iocs(body)

    # Live intelligence
    domain_intelligence = enrich_analysis(iocs, received_chain)
    reputation = build_reputation(iocs)

    # Risk engine
    risk = calculate_risk(
    iocs=iocs,
    headers=headers,
    authentication=authentication,
    routing=routing,
    attachments=attachments,
    domain_intelligence=domain_intelligence,
    reputation=reputation,
)

    metadata = {
        "email_sha256": hashlib.sha256(email_bytes).hexdigest(),
        "size_bytes": len(email_bytes),
        "parser_version": PARSER_VERSION,
    }

    return {
        "metadata": metadata,
        "headers": headers,
        "authentication": authentication,
        "body_preview": body[:500],
        "body_length": len(body),
        "attachments": attachments,
        "iocs": iocs,
        "risk": risk,
        "routing": routing,
        "domain_intelligence": domain_intelligence,
        "reputation": reputation,
    }