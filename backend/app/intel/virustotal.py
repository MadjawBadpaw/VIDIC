import os
import time
import base64
from datetime import datetime, timezone

import httpx
from dotenv import load_dotenv

# ==========================================================
# Load Environment Variables
# ==========================================================

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3"
TIMEOUT = 15

HEADERS = {
    "x-apikey": VT_API_KEY or "",
    "User-Agent": "VIDIC/1.0.0",
}


# ==========================================================
# Helpers
# ==========================================================

def encode_url(url: str) -> str:
    """VirusTotal URL identifier."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def iso_timestamp(unix_ts):
    if not unix_ts:
        return None

    return datetime.fromtimestamp(
        unix_ts,
        tz=timezone.utc
    ).isoformat()


def vt_verdict(stats: dict):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    if malicious > 0:
        return f"Detected as malicious by {malicious} security engine(s)."

    if suspicious > 0:
        return f"Flagged as suspicious by {suspicious} security engine(s)."

    if harmless > 0:
        return "No engines currently detect this URL as malicious."

    return "No reputation available yet."


# ==========================================================
# Submit URL
# ==========================================================

def submit_url(client: httpx.Client, url: str):
    try:
        response = client.post(
            f"{BASE_URL}/urls",
            headers=HEADERS,
            data={"url": url},
        )

        if response.status_code not in (200, 202):
            return None

        return response.json()["data"]["id"]

    except Exception:
        return None


# ==========================================================
# Fetch Analysis
# ==========================================================

def fetch_analysis(client: httpx.Client, analysis_id: str):
    try:
        response = client.get(
            f"{BASE_URL}/analyses/{analysis_id}",
            headers=HEADERS,
        )

        if response.status_code != 200:
            return None

        attrs = response.json()["data"]["attributes"]

        return {
            "status": attrs.get("status"),
            "stats": attrs.get("stats", {}),
        }

    except Exception:
        return None


# ==========================================================
# Fetch Existing URL Reputation
# ==========================================================

def fetch_existing(client: httpx.Client, url: str):
    try:
        response = client.get(
            f"{BASE_URL}/urls/{encode_url(url)}",
            headers=HEADERS,
        )

        if response.status_code == 404:
            return None

        if response.status_code == 401:
            return {"status": "unauthorized"}

        if response.status_code == 429:
            return {"status": "rate_limited"}

        if response.status_code != 200:
            return {"status": "lookup_failed"}

        attrs = response.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})

        return {
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}),
            "last_analysis_date": iso_timestamp(
                attrs.get("last_analysis_date")
            ),
            "last_submission_date": iso_timestamp(
                attrs.get("last_submission_date")
            ),
            "verdict": vt_verdict(stats),
        }

    except httpx.TimeoutException:
        return {"status": "timeout"}

    except Exception:
        return {"status": "lookup_failed"}


# ==========================================================
# Public Batch Lookup
# ==========================================================

def lookup_urls(urls: list[str]):
    """
    Returns:
    {
      "<url>": {
         status,
         malicious,
         suspicious,
         harmless,
         undetected,
         timeout,
         reputation,
         categories,
         verdict,
         last_analysis_date,
         last_submission_date
      }
    }
    """

    if not VT_API_KEY:
        return {
            url: {
                "status": "api_key_missing",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "timeout": 0,
                "reputation": 0,
                "categories": {},
                "last_analysis_date": None,
                "last_submission_date": None,
                "verdict": "VirusTotal API key not configured.",
            }
            for url in urls
        }

    results = {}

    with httpx.Client(timeout=TIMEOUT) as client:

        for url in urls:

            existing = fetch_existing(client, url)

            # Already analysed
            if existing is not None:
                results[url] = existing
                continue

            # Submit new URL
            analysis_id = submit_url(client, url)

            if not analysis_id:
                results[url] = {
                    "status": "submission_failed",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "timeout": 0,
                    "reputation": 0,
                    "categories": {},
                    "last_analysis_date": None,
                    "last_submission_date": None,
                    "verdict": "Failed to submit URL to VirusTotal.",
                }
                continue

            analysis = None

            # Poll for completion (max 10 seconds)
            for _ in range(5):
                time.sleep(2)
                analysis = fetch_analysis(client, analysis_id)

                if (
                    analysis
                    and analysis.get("status") == "completed"
                ):
                    break

            if not analysis:
                results[url] = {
                    "status": "analysis_pending",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "timeout": 0,
                    "reputation": 0,
                    "categories": {},
                    "last_analysis_date": None,
                    "last_submission_date": None,
                    "verdict": "Analysis still pending on VirusTotal.",
                }
                continue

            stats = analysis.get("stats", {})

            results[url] = {
                "status": analysis.get("status"),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0),
                "reputation": 0,
                "categories": {},
                "last_analysis_date": None,
                "last_submission_date": None,
                "analysis_id": analysis_id,
                "verdict": vt_verdict(stats),
            }

    return results