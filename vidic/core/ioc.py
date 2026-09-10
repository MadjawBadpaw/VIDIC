# IOC Extractor (Phase 2)
# Extracts URLs, domains, IPs, sender email addresses, and attachment
# hashes from a parsed email. No network calls, fully offline.

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email.utils import parseaddr
from urllib.parse import urlparse

from vidic.core.parser import ParsedEmail

_URL_RE = re.compile(r'\bhttps?://[^\s<>()]+', re.IGNORECASE)
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
_IPV4_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_IPV6_RE = re.compile(r'\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})\b')
_URL_TRAILING_PUNCTUATION = '.,;:!?)]}'


@dataclass(frozen=True)
class IOC:
    type: str
    value: str
    source: str


class IOCExtractor:
    def extract(self, parsed: ParsedEmail) -> list[IOC]:
        found = {}

        def add(ioc_type, value, source):
            value = value.strip()
            if not value:
                return
            key = (ioc_type, value.lower())
            found.setdefault(key, IOC(type=ioc_type, value=value, source=source))

        self._extract_urls_and_domains(parsed, add)
        self._extract_ips(parsed, add)
        self._extract_emails(parsed, add)
        self._extract_attachment_hashes(parsed, add)

        return list(found.values())

    def _extract_urls_and_domains(self, parsed, add):
        for source_label, text in [('body', parsed.body_text), ('body_html', parsed.body_html)]:
            if not text:
                continue
            for raw_url in _URL_RE.findall(text):
                url = raw_url.rstrip(_URL_TRAILING_PUNCTUATION)
                add('url', url, source_label)
                hostname = urlparse(url).hostname
                if hostname:
                    add('domain', hostname.lower(), source_label)

    def _extract_ips(self, parsed, add):
        for source_label, text in [('body', parsed.body_text), ('body_html', parsed.body_html)]:
            if not text:
                continue
            for candidate in _IPV4_RE.findall(text) + _IPV6_RE.findall(text):
                if self._is_valid_ip(candidate):
                    add('ip', candidate, source_label)

        for i, header in enumerate(parsed.received_chain):
            for candidate in _IPV4_RE.findall(header) + _IPV6_RE.findall(header):
                if self._is_valid_ip(candidate):
                    add('ip', candidate, f'received_hop_{i}')

    @staticmethod
    def _is_valid_ip(candidate):
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)

    def _extract_emails(self, parsed, add):
        header_sources = [
            ('header:From', parsed.sender),
            ('header:Return-Path', parsed.return_path),
        ]
        reply_to = parsed.all_headers.get('Reply-To', '')
        if reply_to:
            header_sources.append(('header:Reply-To', reply_to))

        for source_label, header_value in header_sources:
            address = parseaddr(header_value)[1]
            if address:
                add('email', address.lower(), source_label)

        for source_label, text in [('body', parsed.body_text), ('body_html', parsed.body_html)]:
            if not text:
                continue
            for address in _EMAIL_RE.findall(text):
                add('email', address.lower(), source_label)

    def _extract_attachment_hashes(self, parsed, add):
        for attachment in parsed.attachments:
            add('hash', attachment.sha256, f'attachment:{attachment.filename}')