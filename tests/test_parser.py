"""Basic tests for the Phase 0 email parser."""

from vidic.core.parser import EmailParser

SAMPLE_EML = b"""\
From: "Suspicious Sender" <attacker@evil-example.com>
To: victim@example.com
Return-Path: <bounce@totally-different-domain.com>
Subject: Urgent: verify your account
Date: Mon, 07 Sep 2026 10:00:00 +0000
Message-ID: <abc123@evil-example.com>
Received: from mail.evil-example.com (1.2.3.4) by mx.example.com; Mon, 07 Sep 2026 10:00:01 +0000
Content-Type: text/plain; charset="utf-8"

Please click here to verify your account immediately.
"""


def test_parses_basic_headers():
    parser = EmailParser()
    result = parser.parse_bytes(SAMPLE_EML)

    assert result.subject == "Urgent: verify your account"
    assert "attacker@evil-example.com" in result.sender
    assert "bounce@totally-different-domain.com" in result.return_path
    assert result.recipients == ["victim@example.com"]
    assert "verify your account" in result.body_text
    assert len(result.received_chain) == 1
    assert result.attachments == []
    assert result.parse_warnings == []


def test_handles_missing_file(tmp_path):
    from vidic.core.parser import EmailParseError

    parser = EmailParser()
    missing = tmp_path / "does_not_exist.eml"

    try:
        parser.parse_file(missing)
        assert False, "expected EmailParseError"
    except EmailParseError:
        pass
