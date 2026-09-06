from datetime import datetime, timezone

import httpx
import tldextract
from dateutil.parser import parse as parse_date

client = httpx.Client(
    timeout=8,
    follow_redirects=True,
    headers={"User-Agent": "VIDIC/0.4.0 RDAP Client"},
)


def registered_domain(domain: str) -> str:
    ext = tldextract.extract(domain.lower())
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain.lower()


# ------------------------------------------------------
# Helpers
# ------------------------------------------------------

def extract_creation_date(data: dict):
    """
    Find the domain registration date from RDAP events.
    """
    for event in data.get("events", []):
        action = (event.get("eventAction") or "").lower()

        if action in ("registration", "registered"):
            return event.get("eventDate")

    return None


def extract_registrar(data: dict):
    """
    Registrars appear differently across TLDs.
    Search every entity and vCard.
    """
    for entity in data.get("entities", []):
        vcard = entity.get("vcardArray")

        if not vcard or len(vcard) < 2:
            continue

        fields = vcard[1]

        roles = entity.get("roles", [])

        if "registrar" in roles:
            for field in fields:
                if field[0] in ("fn", "org"):
                    return field[3]

    # fallback
    for entity in data.get("entities", []):
        vcard = entity.get("vcardArray")

        if not vcard or len(vcard) < 2:
            continue

        for field in vcard[1]:
            if field[0] == "fn":
                return field[3]

    return "Unknown Registrar"


def calculate_age(created):
    if not created:
        return None

    try:
        created_date = parse_date(created)
        return (datetime.now(timezone.utc) - created_date).days
    except Exception:
        return None


# ------------------------------------------------------
# Public API
# ------------------------------------------------------

def lookup_domain(domain: str):
    root = registered_domain(domain)

    try:
        response = client.get(f"https://rdap.org/domain/{root}")

        if response.status_code != 200:
            return {
                "domain": root,
                "registrar": None,
                "created": None,
                "age_days": None,
                "tld": root.split(".")[-1],
                "status": "lookup_failed",
            }

        data = response.json()

    except Exception:
        return {
            "domain": root,
            "registrar": None,
            "created": None,
            "age_days": None,
            "tld": root.split(".")[-1],
            "status": "offline_or_lookup_failed",
        }

    created = extract_creation_date(data)

    return {
        "domain": root,
        "registrar": extract_registrar(data),
        "created": created,
        "age_days": calculate_age(created),
        "tld": root.split(".")[-1],
        "status": "ok",
    }