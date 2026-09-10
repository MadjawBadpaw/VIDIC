"""
Email Parser Module (Phase 0/1)

Parses raw .eml files into a structured, dataclass-based representation.
Uses only Python's standard library `email` package — no network calls,
no third-party dependencies. This keeps parsing fast, deterministic, and
safe to run on untrusted/malformed input.

Later phases (Auth Engine, IOC Extractor) will consume the raw_bytes and
headers exposed here without re-parsing the file.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class ParsedEmail:
    # Core headers
    subject: str = ""
    sender: str = ""          # "From" header, as-is
    return_path: str = ""     # "Return-Path" header, as-is
    recipients: list[str] = field(default_factory=list)
    date: str = ""
    message_id: str = ""

    # Content
    body_text: str = ""
    body_html: str = ""

    # Structural / forensic data
    received_chain: list[str] = field(default_factory=list)
    all_headers: dict[str, str] = field(default_factory=dict)
    attachments: list[AttachmentInfo] = field(default_factory=list)

    # Raw bytes — required later for DKIM re-verification, which needs
    # the exact original byte sequence (canonicalization is sensitive
    # to any re-serialization).
    raw_bytes: bytes = b""

    # Populated if parsing hit a recoverable issue (e.g. malformed
    # header) so the UI can surface a warning without failing FR-2.
    parse_warnings: list[str] = field(default_factory=list)


class EmailParseError(Exception):
    """Raised only for unrecoverable failures (e.g. file not .eml-like)."""


class EmailParser:
    """Parses a single .eml file into a ParsedEmail object."""

    def parse_file(self, path: str | Path) -> ParsedEmail:
        path = Path(path)
        if not path.exists():
            raise EmailParseError(f"File not found: {path}")

        raw_bytes = path.read_bytes()
        return self.parse_bytes(raw_bytes)

    def parse_bytes(self, raw_bytes: bytes) -> ParsedEmail:
        result = ParsedEmail(raw_bytes=raw_bytes)

        try:
            msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(
                raw_bytes
            )
        except Exception as exc:  # noqa: BLE001 - we want to catch anything here
            raise EmailParseError(f"Failed to parse email: {exc}") from exc

        self._extract_headers(msg, result)
        self._extract_body(msg, result)
        self._extract_attachments(msg, result)

        return result

    # -- internal helpers -------------------------------------------------

    def _extract_headers(self, msg: EmailMessage, result: ParsedEmail) -> None:
        result.subject = self._safe_header(msg, "Subject")
        result.sender = self._safe_header(msg, "From")
        result.return_path = self._safe_header(msg, "Return-Path")
        result.date = self._safe_header(msg, "Date")
        result.message_id = self._safe_header(msg, "Message-ID")

        to_header = self._safe_header(msg, "To")
        result.recipients = [addr.strip() for addr in to_header.split(",") if addr.strip()]

        # Preserve every header for the "Raw Headers" forensic view (Page 2).
        for key in msg.keys():
            try:
                result.all_headers[key] = str(msg.get(key, ""))
            except Exception:  # noqa: BLE001
                result.parse_warnings.append(f"Could not decode header: {key}")

        # Received chain, in order encountered (top = most recent hop).
        result.received_chain = msg.get_all("Received", [])

    def _extract_body(self, msg: EmailMessage, result: ParsedEmail) -> None:
        try:
            plain_part = msg.get_body(preferencelist=("plain",))
            if plain_part is not None:
                result.body_text = plain_part.get_content()
        except Exception as exc:  # noqa: BLE001
            result.parse_warnings.append(f"Could not extract plain text body: {exc}")

        try:
            html_part = msg.get_body(preferencelist=("html",))
            if html_part is not None:
                result.body_html = html_part.get_content()
        except Exception as exc:  # noqa: BLE001
            result.parse_warnings.append(f"Could not extract HTML body: {exc}")

    def _extract_attachments(self, msg: EmailMessage, result: ParsedEmail) -> None:
        for part in msg.iter_attachments():
            try:
                filename = part.get_filename() or "(unnamed)"
                content = part.get_content()
                if isinstance(content, str):
                    content = content.encode("utf-8", errors="replace")
                digest = hashlib.sha256(content).hexdigest()
                result.attachments.append(
                    AttachmentInfo(
                        filename=filename,
                        content_type=part.get_content_type(),
                        size_bytes=len(content),
                        sha256=digest,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                result.parse_warnings.append(f"Could not process an attachment: {exc}")

    @staticmethod
    def _safe_header(msg: EmailMessage, name: str) -> str:
        try:
            value = msg.get(name, "")
            return str(value) if value is not None else ""
        except Exception:  # noqa: BLE001
            return ""
