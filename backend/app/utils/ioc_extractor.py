import hashlib
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

URL_REGEX = r"https?://[^\s\"'>]+"
EMAIL_REGEX = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"


def sha256_bytes(data: bytes):
    return hashlib.sha256(data).hexdigest()


def extract_iocs(body: str):
    soup = BeautifulSoup(body or "", "lxml")
    text = soup.get_text(" ")

    urls = sorted(set(re.findall(URL_REGEX, body or "")))

    emails = sorted(
        set(email.lower() for email in re.findall(EMAIL_REGEX, text))
    )

    ips = sorted(set(re.findall(IP_REGEX, text)))

    domains = sorted(
        set(
            urlparse(url).hostname.lower()
            for url in urls
            if urlparse(url).hostname
        )
    )

    return {
        "urls": urls,
        "domains": domains,
        "emails": emails,
        "ips": ips,
        "counts": {
            "urls": len(urls),
            "domains": len(domains),
            "emails": len(emails),
            "ips": len(ips),
        },
    }