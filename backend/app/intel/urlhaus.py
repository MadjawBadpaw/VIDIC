import os
import httpx
from dotenv import load_dotenv

load_dotenv()

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
TIMEOUT = 15

URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")


def lookup_urlhaus(url: str):
    """
    Query URLhaus for a single URL.

    Returns:
    {
        status: malicious | clean | unavailable | lookup_failed,
        threat: str | None,
        url_status: str | None,
        tags: list,
        reporter: str | None
    }
    """

    if not URLHAUS_AUTH_KEY:
        return {
            "status": "unavailable",
            "threat": None,
            "url_status": None,
            "tags": [],
            "reporter": None,
        }

    headers = {
        "Auth-Key": URLHAUS_AUTH_KEY,
        "User-Agent": "VIDIC/1.0.0",
    }

    try:
        response = httpx.post(
            URLHAUS_API,
            headers=headers,
            data={"url": url},
            timeout=TIMEOUT,
        )

        response.raise_for_status()
        data = response.json()

        query_status = data.get("query_status")

        if query_status == "no_results":
            return {
                "status": "clean",
                "threat": None,
                "url_status": None,
                "tags": [],
                "reporter": None,
            }

        if query_status == "ok":
            return {
                "status": "malicious",
                "threat": data.get("threat"),
                "url_status": data.get("url_status"),
                "tags": data.get("tags", []),
                "reporter": data.get("reporter"),
            }

        return {
            "status": query_status or "lookup_failed",
            "threat": None,
            "url_status": None,
            "tags": [],
            "reporter": None,
        }

    except httpx.HTTPStatusError as e:
        return {
            "status": f"http_{e.response.status_code}",
            "threat": None,
            "url_status": None,
            "tags": [],
            "reporter": None,
        }

    except Exception as e:
        return {
            "status": "lookup_failed",
            "error": str(e),
            "threat": None,
            "url_status": None,
            "tags": [],
            "reporter": None,
        }


def lookup_urls_urlhaus(urls: list[str]):
    return {url: lookup_urlhaus(url) for url in urls}