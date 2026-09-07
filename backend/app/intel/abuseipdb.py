import os
import httpx
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 15

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def lookup_abuseipdb(ip: str):
    """
    Query AbuseIPDB for a public IP address.

    Returns a normalized dictionary compatible with VIDIC.
    """

    if not ABUSEIPDB_API_KEY:
        return {
            "status": "unavailable",
            "abuse_confidence_score": None,
            "country": None,
            "isp": None,
            "usage_type": None,
            "reports": None,
            "last_reported": None,
        }

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
        "User-Agent": "VIDIC/1.1.0",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True,
    }

    try:
        response = httpx.get(
            ABUSEIPDB_API,
            headers=headers,
            params=params,
            timeout=TIMEOUT,
        )

        if response.status_code == 401:
            return {
                "status": "unauthorized",
                "abuse_confidence_score": None,
                "country": None,
                "isp": None,
                "usage_type": None,
                "reports": None,
                "last_reported": None,
            }

        if response.status_code == 429:
            return {
                "status": "rate_limited",
                "abuse_confidence_score": None,
                "country": None,
                "isp": None,
                "usage_type": None,
                "reports": None,
                "last_reported": None,
            }

        response.raise_for_status()

        data = response.json()["data"]

        confidence = data.get("abuseConfidenceScore", 0)

        if confidence >= 80:
            status = "malicious"
        elif confidence >= 30:
            status = "suspicious"
        else:
            status = "clean"

        return {
            "status": status,
            "abuse_confidence_score": confidence,
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
        }

    except httpx.HTTPError:
        return {
            "status": "lookup_failed",
            "abuse_confidence_score": None,
            "country": None,
            "isp": None,
            "usage_type": None,
            "reports": None,
            "last_reported": None,
        }

    except Exception:
        return {
            "status": "lookup_failed",
            "abuse_confidence_score": None,
            "country": None,
            "isp": None,
            "usage_type": None,
            "reports": None,
            "last_reported": None,
        }