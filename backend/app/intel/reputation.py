from app.intel.virustotal import lookup_urls
from app.intel.urlhaus import lookup_urls_urlhaus


def build_reputation(iocs: dict):
    """
    Build reputation results for every URL found in the email.
    Uses VirusTotal + URLhaus.
    """

    urls = iocs.get("urls", [])

    if not urls:
        return {}

    vt_results = lookup_urls(urls)
    uh_results = lookup_urls_urlhaus(urls)

    reputation = {}

    for url in urls:
        reputation[url] = {
            "virustotal": vt_results.get(
                url,
                {
                    "status": "unavailable",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "timeout": 0,
                    "reputation": 0,
                },
            ),
            "urlhaus": uh_results.get(
                url,
                {
                    "status": "unavailable",
                    "threat": None,
                    "url_status": None,
                    "tags": [],
                    "reporter": None,
                },
            ),
        }

    return reputation