import re
import hashlib
from urllib.parse import urlparse

from bs4 import BeautifulSoup

URL_REGEX = r"https?://[^\s\"'<>]+"
IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
EMAIL_REGEX = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"


def sha256_bytes(data: bytes):
    return hashlib.sha256(data).hexdigest()


def extract_iocs(body: str):
    soup = BeautifulSoup(body, "lxml")
    text = soup.get_text(" ")

    urls = list(set(re.findall(URL_REGEX, body)))
    ips = list(set(re.findall(IP_REGEX, text)))
    emails = list(set(re.findall(EMAIL_REGEX, text)))

    domains = sorted(
        list(
            set(
                urlparse(url).hostname
                for url in urls
                if urlparse(url).hostname
            )
        )
    )

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "emails": emails,
    }